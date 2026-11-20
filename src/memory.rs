//! Executable memory and code patching.

use std::ffi::c_void;

use windows::Win32::{
    Foundation::GetLastError,
    System::{
        Diagnostics::Debug::FlushInstructionCache,
        Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE,
            VirtualAlloc, VirtualFree, VirtualProtect,
        },
        Threading::GetCurrentProcess,
    },
};

use crate::Error;

const PAGE: usize = 0x1000;
const GRAN: usize = 0x10000;
const RESERVE_COMMIT: VIRTUAL_ALLOCATION_TYPE = VIRTUAL_ALLOCATION_TYPE(MEM_COMMIT.0 | MEM_RESERVE.0);

/// How far a rel32 reaches, minus a safety margin.
pub(crate) const NEAR: usize = 0x7FF0_0000;

pub(crate) fn round_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

unsafe fn try_at(addr: usize, size: usize) -> Option<*mut u8> {
    let ptr = VirtualAlloc(Some(addr as *const c_void), size, RESERVE_COMMIT, PAGE_EXECUTE_READWRITE);
    if ptr.is_null() { None } else { Some(ptr as *mut u8) }
}

/// A page-aligned `PAGE_EXECUTE_READWRITE` allocation, freed on drop.
pub(crate) struct Block {
    ptr: *mut u8,
}

unsafe impl Send for Block {}

impl Block {
    /// Allocate `need` bytes as close to `target` as the address space allows.
    ///
    /// A 32-bit address space reaches everywhere with a rel32, so proximity
    /// only matters on x86-64, where it keeps RIP-relative copies and the patch
    /// jump in range.
    pub(crate) unsafe fn near(target: usize, need: usize) -> Result<Block, Error> {
        let size = round_up(need, PAGE);
        if cfg!(target_pointer_width = "32") {
            return Block::any(size);
        }

        let anchor = target & !(GRAN - 1);
        for step in 1..=(NEAR / GRAN) {
            let delta = step * GRAN;
            let low = anchor.checked_sub(delta).filter(|addr| target - addr <= NEAR);
            if let Some(ptr) = low.and_then(|addr| try_at(addr, size)) {
                return Ok(Block { ptr });
            }
            let high = anchor.checked_add(delta).filter(|addr| addr - target <= NEAR);
            if let Some(ptr) = high.and_then(|addr| try_at(addr, size)) {
                return Ok(Block { ptr });
            }
        }
        // Nothing within reach: still usable when no instruction needs re-basing.
        Block::any(size)
    }

    pub(crate) unsafe fn any(size: usize) -> Result<Block, Error> {
        let ptr = VirtualAlloc(None, size, RESERVE_COMMIT, PAGE_EXECUTE_READWRITE);
        if ptr.is_null() {
            return Err(Error::Alloc(GetLastError().0));
        }
        Ok(Block { ptr: ptr as *mut u8 })
    }

    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// True when a rel32 from `addr` reaches this block.
    pub(crate) fn reachable_from(&self, addr: usize) -> bool {
        (self.ptr as usize).abs_diff(addr) <= NEAR
    }

    pub(crate) unsafe fn flush(&self, len: usize) {
        let _ = FlushInstructionCache(GetCurrentProcess(), Some(self.ptr as *const c_void), len);
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.ptr as *mut c_void, 0, MEM_RELEASE);
        }
    }
}

/// Overwrite live code with `bytes`, keeping the page's previous protection.
pub(crate) unsafe fn patch(dst: *mut u8, bytes: &[u8]) -> Result<(), Error> {
    let mut old = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(dst as *const c_void, bytes.len(), PAGE_EXECUTE_READWRITE, &mut old)
        .map_err(|e| Error::Protect(e.code().0 as u32))?;
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
    let _ = FlushInstructionCache(GetCurrentProcess(), Some(dst as *const c_void), bytes.len());
    let mut restored = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(dst as *const c_void, bytes.len(), old, &mut restored)
        .map_err(|e| Error::Protect(e.code().0 as u32))?;
    Ok(())
}
