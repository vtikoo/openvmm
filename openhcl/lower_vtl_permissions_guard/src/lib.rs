// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Implements a VtlMemoryProtection guard that can be used to temporarily allow
//! access to pages that were previously protected.

#![cfg(target_os = "linux")]

mod device_dma;

pub use device_dma::LowerVtlDmaBuffer;

use anyhow::Context;
use anyhow::Result;
use hvdef::HV_PAGE_SIZE;
use hvdef::HvMapGpaFlags;
use hvdef::Vtl;
use hvdef::hypercall::HostVisibilityType;
use inspect::Inspect;
use memory_range::MemoryRange;
use std::sync::Arc;
use underhill_mem::MemoryAcceptor;
use user_driver::DmaClient;
use user_driver::memory::MemoryBlock;
use virt::IsolationType;
use virt::VtlMemoryProtection;

/// A guard that will restore [`hvdef::HV_MAP_GPA_PERMISSIONS_NONE`] permissions
/// on the pages when dropped.
#[derive(Inspect)]
struct PagesAccessibleToLowerVtl {
    #[inspect(skip)]
    vtl_protect: Arc<dyn VtlMemoryProtection + Send + Sync>,
    #[inspect(hex, iter_by_index)]
    pages: Vec<u64>,
    #[inspect(skip)]
    memory_acceptor: Option<MemoryAcceptor>,
}

impl PagesAccessibleToLowerVtl {
    /// Creates a new guard that will lower the VTL permissions of the pages
    /// while the returned guard is held.
    fn new_from_pages(
        vtl_protect: Arc<dyn VtlMemoryProtection + Send + Sync>,
        pages: &[u64],
        isolation_type: IsolationType,
    ) -> Result<Self> {
        let memory_acceptor = if isolation_type.is_isolated() {
            Some(MemoryAcceptor::new(isolation_type)?)
        } else {
            None
        };

        match memory_acceptor.as_ref() {
            Some(memory_acceptor) => {
                // Change protections on the pages to allow VTL0 private access using hardware specific mechanism.
                for pfn in pages {
                    memory_acceptor
                        .apply_protections_for_vtl0(
                            MemoryRange::new((*pfn * HV_PAGE_SIZE)..((*pfn + 1) * HV_PAGE_SIZE)),
                            HvMapGpaFlags::new().with_readable(true).with_writable(true),
                        )
                        .context("failed to adjust pages to VTL0 in PagesAccessibleToLowerVtl")?;
                }
            }
            None => {
                // Otherwise, for non-isolated VMs, change protections on the pages to allow VTL0 access by hypercall.
                for pfn in pages {
                    vtl_protect
                        .modify_vtl_page_setting(*pfn, hvdef::HV_MAP_GPA_PERMISSIONS_ALL)
                        .context("failed to update VTL protections on page")?;
                }
            }
        };

        Ok(Self {
            vtl_protect,
            pages: pages.to_vec(),
            memory_acceptor,
        })
    }
}

impl Drop for PagesAccessibleToLowerVtl {
    fn drop(&mut self) {
        // [TDISP TODO] Fix all of this to use a proper memory acceptor.
        if let Some(memory_acceptor) = self.memory_acceptor.as_ref() {
            // Change protections on the pages to allow VTL0 private access using hardware specific mechanism.
            for pfn in &self.pages {
                memory_acceptor
                    .apply_protections_for_vtl2(
                        MemoryRange::new((*pfn * HV_PAGE_SIZE)..((*pfn + 1) * HV_PAGE_SIZE)),
                        HvMapGpaFlags::new().with_readable(true).with_writable(true),
                    )
                    .context("failed to return pages to VTL2 in PagesAccessibleToLowerVtl")
                    .unwrap();
            }

            return;
        }

        if let Err(err) = self
            .pages
            .iter()
            .map(|pfn| {
                self.vtl_protect
                    .modify_vtl_page_setting(*pfn, hvdef::HV_MAP_GPA_PERMISSIONS_NONE)
                    .context("failed to update VTL protections on page")
            })
            .collect::<Result<Vec<_>>>()
        {
            // The inability to rollback any pages is fatal. We cannot leave the
            // pages in the state where the correct VTL protections are not
            // applied, because that would compromise the security of the
            // platform.
            panic!(
                "failed to reset page protections {}",
                err.as_ref() as &dyn std::error::Error
            );
        }
    }
}

/// A [`DmaClient`] wrapper that will lower the VTL permissions of the page
/// on the allocated memory block.
#[derive(Inspect)]
pub struct LowerVtlMemorySpawner<T: DmaClient> {
    #[inspect(skip)]
    spawner: T,
    #[inspect(skip)]
    vtl_protect: Arc<dyn VtlMemoryProtection + Send + Sync>,
    isolation_type: IsolationType,
}

impl<T: DmaClient> LowerVtlMemorySpawner<T> {
    /// Create a new wrapped [`DmaClient`] spawner that will lower the VTL
    /// permissions of the returned [`MemoryBlock`].
    pub fn new(
        spawner: T,
        vtl_protect: Arc<dyn VtlMemoryProtection + Send + Sync>,
        isolation_type: IsolationType,
    ) -> Self {
        Self {
            spawner,
            vtl_protect,
            isolation_type,
        }
    }
}

impl<T: DmaClient> DmaClient for LowerVtlMemorySpawner<T> {
    fn allocate_dma_buffer(&self, len: usize) -> Result<MemoryBlock> {
        let mem = self.spawner.allocate_dma_buffer(len)?;
        let vtl_guard = PagesAccessibleToLowerVtl::new_from_pages(
            self.vtl_protect.clone(),
            mem.pfns(),
            self.isolation_type,
        )
        .context("failed to lower VTL permissions on memory block")?;

        Ok(MemoryBlock::new(LowerVtlDmaBuffer {
            block: mem,
            _vtl_guard: vtl_guard,
        }))
    }

    fn attach_pending_buffers(&self) -> Result<Vec<MemoryBlock>> {
        anyhow::bail!("restore is not supported for LowerVtlMemorySpawner")
    }
}
