// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The module implements Linux SEV-SNP Guest APIs based on ioctl.

// UNSAFETY: unsafe needed to make ioctl calls.
#![expect(unsafe_code)]

use crate::protocol;
use std::fs::File;
use std::os::fd::AsRawFd;
use thiserror::Error;
use zerocopy::FromBytes;
use zerocopy::FromZeros;
use zerocopy::Immutable;
use zerocopy::IntoBytes;

#[expect(missing_docs)] // self-explanatory fields
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to open /dev/sev-guest")]
    OpenDevSevGuest(#[source] std::io::Error),
    #[error("SNP_GET_REPORT ioctl failed")]
    SnpGetReportIoctl(#[source] nix::Error),
    #[error("SNP_GET_DERIVED_KEY ioctl failed")]
    SnpGetDerivedKeyIoctl(#[source] nix::Error),
    #[error("TIO_GUEST_REQUEST ioctl failed")]
    TioGuestRequestIoctl(#[source] nix::Error),
}

nix::ioctl_readwrite!(
    /// `SNP_GET_REPORT` ioctl defined by Linux.
    snp_get_report,
    protocol::SNP_GUEST_REQ_IOC_TYPE,
    0x0,
    // [TDISP TODO] Change this back since this is hacked to be a different struct right now.
    protocol::TioGuestRequestIoctl
);

nix::ioctl_readwrite!(
    /// `SNP_GET_DERIVED_KEY` ioctl defined by Linux.
    snp_get_derived_key,
    protocol::SNP_GUEST_REQ_IOC_TYPE,
    0x1,
// [TDISP TODO] Change this back since this is hacked to be a different struct right now.
    protocol::TioGuestRequestIoctl
);

nix::ioctl_readwrite!(
    /// `TIO_GUEST_REQUEST` ioctl defined by Linux.
    tio_guest_request,
    protocol::SNP_GUEST_REQ_IOC_TYPE,
    0x3,
    // [TDISP TODO] Use proper interface for this.
    protocol::TioGuestRequestIoctl
);

/// Abstraction of the /dev/sev-guest device.
pub struct SevGuestDevice {
    file: File,
}

impl SevGuestDevice {
    /// Open an /dev/sev-guest device
    pub fn open() -> Result<Self, Error> {
        let sev_guest = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/sev-guest")
            .map_err(Error::OpenDevSevGuest)?;

        Ok(Self { file: sev_guest })
    }

    /// Invoke the `SNP_GET_REPORT` ioctl via the device.
    pub fn get_report(&self, user_data: [u8; 64], vmpl: u32) -> Result<protocol::SnpReport, Error> {
        let req = protocol::SnpReportReq {
            user_data,
            vmpl,
            rsvd: [0u8; 28],
        };

        let resp = protocol::SnpReportResp::new_zeroed();

        let mut snp_guest_request = protocol::TioGuestRequestIoctl {
            msg_version: protocol::SNP_GUEST_REQ_MSG_VERSION,
            req_data: req.as_bytes().as_ptr() as u64,
            resp_data: resp.as_bytes().as_ptr() as u64,
            exitinfo1: protocol::VmmErrorCode::new_zeroed(),
            exitinfo2: 0,
            msg_type: 0,
            req_size: 0,
            resp_size: 0,
            pci_id: 0,
            additional_arg: 0,
        };

        // SAFETY: Make SNP_GET_REPORT ioctl call to the device with correct types.
        unsafe {
            snp_get_report(self.file.as_raw_fd(), &mut snp_guest_request)
                .map_err(Error::SnpGetReportIoctl)?;
        }

        Ok(resp.report)
    }

    /// Invoke the `SNP_GET_DERIVED_KEY` ioctl via the device.
    pub fn get_derived_key(
        &self,
        root_key_select: u32,
        guest_field_select: u64,
        vmpl: u32,
        guest_svn: u32,
        tcb_version: u64,
    ) -> Result<[u8; protocol::SNP_DERIVED_KEY_SIZE], Error> {
        let req = protocol::SnpDerivedKeyReq {
            root_key_select,
            rsvd: 0u32,
            guest_field_select,
            vmpl,
            guest_svn,
            tcb_version,
        };

        let resp = protocol::SnpDerivedKeyResp::new_zeroed();

        let mut snp_guest_request = protocol::TioGuestRequestIoctl {
            msg_version: protocol::SNP_GUEST_REQ_MSG_VERSION,
            req_data: req.as_bytes().as_ptr() as u64,
            resp_data: resp.as_bytes().as_ptr() as u64,
            exitinfo1: protocol::VmmErrorCode::new_zeroed(),
            exitinfo2: 0,
            msg_type: 0,
            req_size: 0,
            resp_size: 0,
            pci_id: 0,
            additional_arg: 0,
        };

        // SAFETY: Make SNP_GET_DERIVED_KEY ioctl call to the device with correct types
        unsafe {
            snp_get_derived_key(self.file.as_raw_fd(), &mut snp_guest_request)
                .map_err(Error::SnpGetReportIoctl)?;
        }

        Ok(resp.derived_key)
    }

    /// Invoke the `TIO_GUEST_REQUEST` ioctl via the device.
    fn tio_guest_request<RequestType, ResponseType>(
        &mut self,
        msg_type: u64,
        guest_device_id: u16,
        req: RequestType,
    ) -> Result<ResponseType, Error>
    where
        RequestType: IntoBytes + Immutable + std::fmt::Debug,
        ResponseType: FromZeros + IntoBytes + Immutable + std::fmt::Debug,
    {
        let resp = ResponseType::new_zeroed();

        tracing::trace!(
            msg = "tio_guest_request issuing ioctl",
            msg_type,
            req = ?req
        );

        let mut snp_guest_request = protocol::TioGuestRequestIoctl {
            msg_version: protocol::SNP_GUEST_REQ_MSG_VERSION,
            req_data: req.as_bytes().as_ptr() as u64,
            resp_data: resp.as_bytes().as_ptr() as u64,
            exitinfo1: protocol::VmmErrorCode::new_zeroed(),
            exitinfo2: 0,
            msg_type,
            req_size: req.as_bytes().len() as u64,
            resp_size: resp.as_bytes().len() as u64,
            pci_id: guest_device_id as u64,
            additional_arg: 0,
        };

        // SAFETY: Make TIO_GUEST_REQUEST ioctl call to the device with correct types
        unsafe {
            tio_guest_request(self.file.as_raw_fd(), &mut snp_guest_request)
                .map_err(Error::TioGuestRequestIoctl)?;
        }

        tracing::info!(
            msg = "tio_guest_request completed successfully",
            req = ?req,
            resp = ?resp
        );

        Ok(resp)
    }

    /// Invoke the `TIO_MSG_TDI_INFO_REQ` to a given TDISP guest device ID.
    pub fn tio_msg_tdi_info_req(
        &mut self,
        guest_device_id: u16,
    ) -> Result<protocol::TioMsgTdiInfoRsp, Error> {
        let msg_type = 19; // TIO_MSG_TDI_INFO_REQ

        let req = protocol::TioMsgTdiInfoReq {
            guest_device_id,
            _reserved0: [0; 14],
        };

        self.tio_guest_request(msg_type, guest_device_id, req)
    }

    /// Invoke the `TIO_MSG_MMIO_CONFIG_REQ` to a given TDISP guest device ID.
    pub fn tio_msg_mmio_config_req(
        &mut self,
        guest_device_id: u16,
        range_id: u16,
    ) -> Result<protocol::TioMsgMmioConfigRsp, Error> {
        let msg_type = 23; // TIO_MSG_MMIO_CONFIG_REQ

        let req = protocol::TioMsgMmioConfigReq {
            guest_device_id,
            _reserved0: [0; 2],
            flags: 0,
            range_id,
            write: 0,
            _reserved2: [0; 4],
        };

        self.tio_guest_request(msg_type, guest_device_id, req)
    }

    /// Invoke the `TIO_MSG_MMIO_VALIDATE_REQ` to a given TDISP guest device ID.
    pub fn tio_msg_mmio_validate_req(
        &mut self,
        guest_device_id: u16,
        subrange_base: u64,
        subrange_page_count: u32,
        range_offset: u32,
        range_id: u16,
        validated: bool,
        force_validated: bool,
    ) -> Result<protocol::TioMsgMmioValidateRsp, Error> {
        let msg_type = 21; // TIO_MSG_MMIO_VALIDATE_REQ 

        let req = protocol::TioMsgMmioValidateReq {
            guest_device_id,
            _reserved0: [0; 14],
            subrange_base,
            subrange_page_count,
            range_offset,
            validated_flags: protocol::TioMsgMmioValidateReqFlags::new()
                .with_force_validated(force_validated)
                .with_validated(validated),
            range_id,
            _reserved2: [0; 12],
        };

        self.tio_guest_request(msg_type, guest_device_id, req)
    }

    /// Invoke the `TIO_MSG_SDTE_WRITE_REQ` to update the SDTE to allow DMA to the guest.
    pub fn tio_msg_sdte_write_req(
        &mut self,
        guest_device_id: u16,
    ) -> Result<protocol::TioMsgSdteWriteRsp, Error> {
        let msg_type = 25; // TIO_MSG_SDTE_WRITE_REQ

        let vtom = 0x7fffffff;
        let vmpl = 2;
        tracing::info!(
            msg = format!("Sending SDTE write request for VMPL {vmpl:?} and vtom {vtom:x?}...")
        );
        let sdte = protocol::Sdte {
            part1: protocol::SdtePart1::new()
                .with_v(true)
                .with_ir(true)
                .with_iw(true),
            _reserved0: 0,
            _reserved1: 0,
            part2: protocol::SdtePart2::new().with_vmpl(vmpl),
            _reserved2: 0,
            part3: protocol::SdtePart3::new()
                .with_vtom_en(true)
                .with_virtual_tom(vtom), // 2MB PFN [TDISP TODO] Update with proper VTOM
            _reserved3: 0,
            _reserved4: 0,
        };

        // Print sdte as a byte buffer
        tracing::info!(msg = format!("SDTE: {:?}", sdte.as_bytes()));

        let req = protocol::TioMsgSdteWriteReq {
            guest_device_id,
            _reserved0: [0; 14],
            sdte,
        };

        self.tio_guest_request(msg_type, guest_device_id, req)
    }
}
