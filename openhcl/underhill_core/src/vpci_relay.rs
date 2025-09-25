use anyhow::Context as _;
use chipset_device::ChipsetDevice;
use chipset_device::io::IoResult;
use chipset_device::pci::PciConfigSpace;
use futures::StreamExt;
use hcl::ioctl::Mshv;
use hcl::ioctl::MshvHvcall;
use hvdef::HvMapGpaFlags;
use hvdef::HypercallCode;
use hvdef::hypercall::HostVisibilityType;
use inspect::InspectMut;
use memory_range::MemoryRange;
use openhcl_tdisp_resources::VpciTdispInterface;
use std::sync::Arc;
use tdisp::GuestToHostCommand;
use tdisp::TdispCommandId;
use tdisp::TdispDeviceReport;
use tdisp::TdispDeviceReportType;
use tdisp::TdispGuestUnbindReason;
use user_driver::DmaClient;
use vmbus_client::local_use::Input;
use vmcore::device_state::ChangeDeviceState;
use vmcore::save_restore::RestoreError;
use vmcore::save_restore::SaveError;
use vmcore::save_restore::SaveRestore;
use vmcore::save_restore::SavedStateNotSupported;
use vmcore::vm_task::VmTaskDriverSource;
use vmcore::vpci_msi::VpciInterruptMapper;
use vmotherboard::ChipsetBuilder;
use vpci_client::MemoryAccess;
use vpci_client::VpciDevice;
use x86defs::snp::SevRmpAdjust;

const TEMP_GPA: u64 = 0x1000000000 - 0x2000;

struct HypercallMmio(MshvHvcall);

struct DirectMmio(sparse_mmap::SparseMapping);

impl MemoryAccess for DirectMmio {
    fn gpa(&mut self) -> u64 {
        TEMP_GPA
    }

    fn read(&mut self, addr: u64) -> u32 {
        let offset = addr
            .checked_sub(self.gpa())
            .and_then(|o| o.try_into().ok())
            .unwrap_or(!0);
        match self.0.read_volatile(offset) {
            Ok(v) => v,
            Err(err) => {
                tracelimit::error_ratelimited!(
                    addr,
                    error = &err as &dyn std::error::Error,
                    "vpci mmio read failure"
                );
                !0
            }
        }
    }

    fn write(&mut self, addr: u64, value: u32) {
        let offset = addr
            .checked_sub(self.gpa())
            .and_then(|o| o.try_into().ok())
            .unwrap_or(!0);
        if let Err(err) = self.0.write_volatile(offset, &value) {
            tracelimit::error_ratelimited!(
                addr,
                value,
                error = &err as &dyn std::error::Error,
                "vpci mmio write failure"
            );
        }
    }
}

impl MemoryAccess for HypercallMmio {
    fn gpa(&mut self) -> u64 {
        TEMP_GPA
    }

    fn read(&mut self, addr: u64) -> u32 {
        let mut data = [0; 4];
        match self.0.mmio_read(addr, &mut data) {
            Ok(()) => u32::from_ne_bytes(data),
            Err(err) => {
                tracelimit::error_ratelimited!(
                    addr,
                    error = &err as &dyn std::error::Error,
                    "vpci mmio read failure"
                );
                !0
            }
        }
    }

    fn write(&mut self, addr: u64, value: u32) {
        let data = value.to_ne_bytes();
        if let Err(err) = self.0.mmio_write(addr, &data) {
            tracelimit::error_ratelimited!(
                addr,
                value,
                error = &err as &dyn std::error::Error,
                "vpci mmio write failure"
            );
        }
    }
}

pub async fn relay_vpci_bus(
    chipset_builder: &mut ChipsetBuilder<'_>,
    driver_source: &VmTaskDriverSource,
    offer_info: vmbus_client::OfferInfo,
    dma_client: &dyn DmaClient,
    vmbus: &vmbus_server::VmbusServerControl,
) -> anyhow::Result<()> {
    let instance_id = offer_info.offer.instance_id;

    let mmio = if true {
        let mshv_hvcall = MshvHvcall::new().context("failed to open mshv_hvcall device")?;
        mshv_hvcall.set_allowed_hypercalls(&[
            hvdef::HypercallCode::HvCallMemoryMappedIoRead,
            hvdef::HypercallCode::HvCallMemoryMappedIoWrite,
        ]);
        Box::new(HypercallMmio(mshv_hvcall)) as _
    } else {
        let mapping = sparse_mmap::SparseMapping::new(0x2000)
            .context("failed to create sparse mapping for vpci mmio")?;
        let dev_mem = fs_err::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mem")
            .context("failed to open /dev/mem")?;
        mapping
            .map_file(0, 0x2000, &dev_mem, TEMP_GPA, true)
            .context("failed to map /dev/mem for vpci mmio")?;

        Box::new(DirectMmio(mapping)) as _
    };

    let channel = vmbus_client::local_use::open_channel(
        driver_source.simple(),
        offer_info,
        Input {
            ring_pages: 20,
            ring_offset_in_pages: 10,
        },
        dma_client,
    )
    .await
    .context("failed to open vpci channel")?;
    let (devices, mut devices_recv) = mesh::channel();
    let vpci_client =
        vpci_client::VpciClient::connect(driver_source.simple(), channel, mmio, devices).await?;
    // TODO: hang onto this guy, wire him up to the inspect graph at least.
    vpci_client.detach();
    let vpci_device = devices_recv.next().await.context("no device")?;
    let vpci_device = Arc::new(
        vpci_device
            .init()
            .await
            .context("failed to initialize vpci device")?,
    );

    let res = vpci_device.tdisp_get_device_interface_info().await;
    tracing::info!(msg = format!("tdisp_get_device_interface_info: {:?}", res));

    let mshv = MshvHvcall::new().unwrap();
    mshv.set_allowed_hypercalls(&[HypercallCode::HvCallModifySparseGpaPageHostVisibility]);

    if let Ok(_) = res {
        let bind_res = vpci_device.tdisp_bind_interface().await;
        tracing::info!(msg = format!("tdisp_bind_interface first time: {:?}", bind_res));

        if let Ok(_) = bind_res {
            let start_res = vpci_device.tdisp_start_device().await;
            tracing::info!(msg = format!("tdisp_start_device first time: {:?}", start_res));

            if let Ok(_) = start_res {
                tracing::info!(msg = "Issuing GHCB call to test TIO_GUEST_REQUEST ioctl");
                let mut dev = sev_guest_device::ioctl::SevGuestDevice::open()
                    .context("failed to open /dev/sev-guest")?;
                tracing::info!(msg = "Opened /dev/sev-guest");

                tracing::info!(msg = "Issuing GHCB call to test TIO_GUEST_REQUEST ioctl");

                let guest_device_id = vpci_device.tdisp_get_tdi_device_id().await?;
                tracing::info!(msg = format!("Guest device ID: {guest_device_id}"));

                // [TDISP TODO] Test getting the attestation digests from the host, but do not validate them.
                dev.tio_msg_tdi_info_req(guest_device_id as u16)
                    .context("failed to issue TIO_GUEST_REQUEST ioctl")?;

                let tdi_report = vpci_device.tdisp_get_tdi_report().await?;
                tracing::info!(tdi_report = ?tdi_report);
            }
        }
    }

    // let unbind_res = vpci_device
    //     .tdisp_unbind(TdispGuestUnbindReason::Graceful)
    //     .await;
    // tracing::info!(msg = format!("tdisp_unbind: {:?}", unbind_res));

    let device_name = format!("assigned_device:vpci-{instance_id}");
    let device = chipset_builder
        .arc_mutex_device(device_name)
        .with_external_pci()
        .add(|_services| RelayedVpciDevice(vpci_device.clone()))?;

    let interrupt_mapper = VpciInterruptMapper::new(vpci_device);

    {
        let vpci_bus_name = format!("vpci:{instance_id}");
        chipset_builder
            .arc_mutex_device(vpci_bus_name)
            .try_add_async(async |services| {
                let bus = vpci::bus::VpciBus::new(
                    driver_source,
                    instance_id,
                    device,
                    &mut services.register_mmio(),
                    vmbus,
                    interrupt_mapper,
                )
                .await?;

                anyhow::Ok(bus)
            })
            .await?;
    }

    Ok(())
}

#[derive(InspectMut)]
#[inspect(transparent)]
pub struct RelayedVpciDevice(Arc<VpciDevice>);

impl ChipsetDevice for RelayedVpciDevice {
    fn supports_pci(&mut self) -> Option<&mut dyn PciConfigSpace> {
        Some(self)
    }
}

impl PciConfigSpace for RelayedVpciDevice {
    fn pci_cfg_read(&mut self, offset: u16, value: &mut u32) -> IoResult {
        *value = self.0.read_cfg(offset);
        IoResult::Ok
    }

    fn pci_cfg_write(&mut self, offset: u16, value: u32) -> IoResult {
        self.0.write_cfg(offset, value);

        // If the write was to the command register, read back programmed
        // BAR values and validate their MMIO ranges.
        tracing::info!(msg = "CFG write", offset, value);
        if offset == 0x4 {
            // This is a command register write, determine if this is a
            // write to enable MMIO.
            let enable_mmio = value & 0x1 != 0;
            tracing::info!(msg = "CFG command register write", enable_mmio);
            if enable_mmio && !self.0.has_attested() {
                self.0.set_attested(true);
                // Get configured BARs
                let bars = self.0.configured_bars();
                tracing::info!(
                    msg = "Command register MMIO enabled",
                    bars = ?bars,
                );

                // Wait 10 seconds to allow debugger to attach
                tracing::info!(msg = "Waiting for debugger to attach...");

                let bar_addresses_hack: [u64; 2] = [0xff7ffd000, 0xff7ffc000]; // ,0xf7ffb000];
                let range_ids: [u16; 2] = [0, 2];

                let mshv = MshvHvcall::new().unwrap();
                mshv.set_allowed_hypercalls(&[
                    HypercallCode::HvCallModifySparseGpaPageHostVisibility,
                    HypercallCode::HvCallModifyVtlProtectionMask,
                ]);

                let mut dev = sev_guest_device::ioctl::SevGuestDevice::open()
                    .context("failed to open /dev/sev-guest")
                    .unwrap();

                // For each of the ranges reported in the TDI report, issue a guest message to validate them.
                for (i, range_id) in range_ids.into_iter().enumerate() {
                    let base: u64 = bar_addresses_hack[i];

                    tracing::info!(
                        msg =
                            format!("Calling to make BAR{range_id} into private pages @ {base:#x}")
                    );

                    let pfn: u64 = base >> hvdef::HV_PAGE_SHIFT;

                    let mshv_vtl_changer = Mshv::new().context("failed to create mshv").unwrap();
                    let mshv_vtl = mshv_vtl_changer
                        .create_vtl()
                        .context("failed to create mshv vtl")
                        .unwrap();

                    // Modify the pages to be acessible to VTL0
                    // This is not used in SNP, this is only used in TDX because SNP paravisors call rmpadjust on their own.
                    // mshv.modify_vtl_protection_mask(
                    //     MemoryRange::from_4k_gpn_range(pfn..pfn + 1),
                    //     HvMapGpaFlags::new().with_readable(true).with_writable(true),
                    //     hvdef::hypercall::HvInputVtl::new()
                    //         .with_target_vtl_value(0)
                    //         .with_use_target_vtl(true),
                    // )
                    // .context("failed to modify VTL page permissions")
                    // .unwrap();

                    // Modify the pages to be private pages before we validate them.
                    mshv.modify_gpa_visibility(HostVisibilityType::PRIVATE, &[pfn])
                        .map_err(|e| anyhow::anyhow!("failed to modify visibility: {e:?}"))
                        .unwrap();

                    tracing::info!(
                        msg = format!("Accepting BAR{range_id} into guest context @ {base:#x}")
                    );

                    // Call to set RMP pages to RMP.Validated=1, but these will be assigned to the highest VMPL (VTL2) until
                    // we adjust them to be readable and writable by VTL0.
                    let response = dev
                        .tio_msg_mmio_validate_req(
                            1, // guest_device_id
                            base, 1, 0, range_id, true, false,
                        )
                        .context("failed to send MMIO validation request")
                        .unwrap();

                    if response.status != 0 {
                        panic!(
                            "MMIO validation request failed for BAR{range_id} (status: {response:?})"
                        );
                    }

                    // Call rmpadjust to set the pages to be readable and writable by VTL0
                    mshv_vtl
                        .rmpadjust_pages(
                            MemoryRange::from_4k_gpn_range(pfn..pfn + 1),
                            SevRmpAdjust::new()
                                .with_enable_read(true)
                                .with_enable_write(true)
                                .with_target_vmpl(2) // VMPL 2 is VTL0, VMPL 0 is VTL2...
                                .with_vmsa(false),
                            false,
                        )
                        .context("failed to modify VTL target for page")
                        .unwrap();

                    tracing::info!(msg = "Done accepting BAR, next loop...");
                    tracing::info!(msg = format!("BAR{range_id} validation response"), response = ?response);
                }

                tracing::info!(msg = "Sending SDTE write request...");
                let accept_dma = dev
                    .tio_msg_sdte_write_req(1)
                    .context("failed to send SDTE write request")
                    .unwrap();
                tracing::info!(msg = format!("SDTE write request response"), response = ?accept_dma);
                if accept_dma.status != 0 {
                    panic!("SDTE write request failed (status: {accept_dma:?})");
                }
            }
        }

        IoResult::Ok
    }
}

impl ChangeDeviceState for RelayedVpciDevice {
    fn start(&mut self) {}

    async fn stop(&mut self) {}

    async fn reset(&mut self) {}
}

impl SaveRestore for RelayedVpciDevice {
    type SavedState = SavedStateNotSupported;

    fn save(&mut self) -> Result<Self::SavedState, SaveError> {
        Err(SaveError::NotSupported)
    }

    fn restore(&mut self, state: Self::SavedState) -> Result<(), RestoreError> {
        match state {}
    }
}
