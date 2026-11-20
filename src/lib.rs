//! `naly` - small, modern inline detours for Windows x86 and x86-64.
//!
//! One patch, one object, no global bookkeeping: [`Hook`] copies the overwritten
//! instructions into a reachable trampoline, rewrites the prologue with a
//! 5-byte jump, and puts everything back when dropped.
//!
//! ```no_run
//! use std::ffi::c_void;
//!
//! type Fn = unsafe extern "system" fn(i32) -> i32;
//!
//! unsafe extern "system" fn detour(x: i32) -> i32 {
//!     // reach the original through the trampoline
//!     x + 1
//! }
//!
//! # unsafe fn demo(target: Fn) {
//! let hook = naly::Hook::attach(target as *mut c_void, detour as *mut c_void).unwrap();
//! let original: Fn = hook.function();
//! # let _ = original;
//! # }
//! ```
//!
//! Threads are frozen while the bytes change, and a thread parked inside the
//! replaced prologue is re-pointed at its copy, so no thread ever resumes into
//! a partially written instruction.

#![allow(unsafe_op_in_unsafe_fn)]

mod decode;
mod memory;
mod threads;

use std::ffi::c_void;
use std::fmt;

use decode::{Insn, Rel};

/// Bytes an inline patch needs: `jmp rel32`.
pub const MIN_PATCH: usize = 5;

/// Upper bound for the prologue bytes that get relocated.
const MAX_STOLEN: usize = 32;

const MAX_INSNS: usize = 32;

const WIDE: bool = cfg!(target_pointer_width = "64");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A null target or detour address was passed.
    Null,
    /// The prologue ended before [`MIN_PATCH`] bytes could be covered.
    Truncated,
    /// The decoder met an encoding this crate refuses to relocate.
    Unsupported {
        /// First byte of the rejected instruction.
        opcode: u8,
    },
    /// A branch or RIP-relative operand cannot be re-based to the trampoline.
    Relocation,
    /// No allocation within a rel32 of the target was available.
    Distance,
    /// `VirtualAlloc` failed with the given Win32 error code.
    Alloc(u32),
    /// `VirtualProtect` failed with the given Win32 error code.
    Protect(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Null => f.write_str("null address"),
            Error::Truncated => f.write_str("prologue too short to patch"),
            Error::Unsupported { opcode } => write!(f, "unsupported instruction encoding 0x{opcode:02X}"),
            Error::Relocation => f.write_str("instruction cannot be relocated into the trampoline"),
            Error::Distance => f.write_str("no free memory within reach of the target"),
            Error::Alloc(code) => write!(f, "VirtualAlloc failed (error {code})"),
            Error::Protect(code) => write!(f, "VirtualProtect failed (error {code})"),
        }
    }
}

impl std::error::Error for Error {}

/// One inline hook.
///
/// Created detached with [`Hook::prepare`], or armed immediately with
/// [`Hook::attach`]. Dropping disables the hook and frees the trampoline.
pub struct Hook {
    target: *mut c_void,
    detour: *mut c_void,
    tramp: *mut u8,
    /// Owns the trampoline page; released only after the patch is removed.
    _block: memory::Block,
    orig: [u8; MAX_STOLEN],
    patch: [u8; MAX_STOLEN],
    stolen: usize,
    map: [(u32, u32); MAX_INSNS],
    insns: usize,
    enabled: bool,
}

unsafe impl Send for Hook {}

impl Hook {
    /// Arm a hook right away.
    pub unsafe fn attach(target: *mut c_void, detour: *mut c_void) -> Result<Hook, Error> {
        let mut hook = Hook::prepare(target, detour)?;
        hook.enable()?;
        Ok(hook)
    }

    /// Build the trampoline and the patch without touching the target yet.
    ///
    /// Use this when the detour needs the trampoline address before it can call
    /// through, then call [`Hook::enable`].
    pub unsafe fn prepare(target: *mut c_void, detour: *mut c_void) -> Result<Hook, Error> {
        if target.is_null() || detour.is_null() {
            return Err(Error::Null);
        }
        let base = target as usize;

        // never read past the page the prologue starts in: the next one may be
        // uncommitted
        let limit = MAX_STOLEN.min(0x1000 - (base & 0xFFF));
        let mut code = [0u8; MAX_STOLEN];
        std::ptr::copy_nonoverlapping(target as *const u8, code.as_mut_ptr(), limit);

        let mut insns = [Insn::ZERO; MAX_INSNS];
        let mut starts = [0u32; MAX_INSNS];
        let mut stolen = 0usize;
        let mut count = 0usize;
        while stolen < MIN_PATCH {
            if count == MAX_INSNS || stolen >= limit {
                return Err(Error::Truncated);
            }
            let start = stolen;
            let insn = decode::decode(&code[start..limit], WIDE)?;
            starts[count] = start as u32;
            insns[count] = insn;
            stolen += insn.len;
            count += 1;
            // walking past the end of the function would patch its neighbour
            if insn.ends && stolen < MIN_PATCH {
                return Err(Error::Truncated);
            }
        }

        // generous room: a short branch can grow into a near one
        let need = 6 * stolen + 64;
        let block = memory::Block::near(base, need)?;
        if WIDE && !block.reachable_from(base) {
            return Err(Error::Distance);
        }

        let mut out = 0usize;
        let mut map = [(0u32, 0u32); MAX_INSNS];
        for k in 0..count {
            map[k] = (starts[k], out as u32);
            let at = starts[k] as usize;
            let dst = block.as_ptr().add(out);
            out += relocate(&insns[k], &code[at..limit], base + at, dst as usize)?;
        }

        // jump back to the first byte after the patch
        let back = base + stolen;
        let here = block.as_ptr().add(out) as usize;
        if WIDE {
            out += write_abs_jump(block.as_ptr().add(out), back);
        } else {
            let delta = back as i64 - (here as i64 + 5);
            let disp = i32::try_from(delta).map_err(|_| Error::Relocation)?;
            let mut stub = [0xE9u8, 0, 0, 0, 0];
            stub[1..].copy_from_slice(&disp.to_le_bytes());
            std::ptr::copy_nonoverlapping(stub.as_ptr(), block.as_ptr().add(out), 5);
            out += 5;
        }

        // the detour usually lives in another module, so reach it through a stub
        // parked next to the trampoline
        let mut used = out;
        let jump_to = if WIDE {
            let at = memory::round_up(out, 16);
            used = at + 14;
            let stub = block.as_ptr().add(at);
            write_abs_jump(stub, detour as usize);
            stub as usize
        } else {
            detour as usize
        };
        block.flush(used);

        let mut patch = [0x90u8; MAX_STOLEN];
        let delta = jump_to as i64 - (base as i64 + 5);
        let disp = i32::try_from(delta).map_err(|_| Error::Distance)?;
        patch[0] = 0xE9;
        patch[1..5].copy_from_slice(&disp.to_le_bytes());

        let mut orig = [0u8; MAX_STOLEN];
        orig[..stolen].copy_from_slice(&code[..stolen]);

        Ok(Hook {
            target,
            detour,
            tramp: block.as_ptr(),
            _block: block,
            orig,
            patch,
            stolen,
            map,
            insns: count,
            enabled: false,
        })
    }

    /// Write the jump into the target.
    pub unsafe fn enable(&mut self) -> Result<(), Error> {
        if self.enabled {
            return Ok(());
        }
        let fix = threads::Fix {
            target: self.target as usize,
            len: self.stolen,
            tramp: self.tramp as usize,
            map: &self.map[..self.insns],
        };
        let frozen = threads::freeze(Some(&fix));
        let result = memory::patch(self.target as *mut u8, &self.patch[..self.stolen]);
        threads::thaw(frozen);
        result?;
        self.enabled = true;
        Ok(())
    }

    /// Restore the original bytes.
    pub unsafe fn disable(&mut self) -> Result<(), Error> {
        if !self.enabled {
            return Ok(());
        }
        let frozen = threads::freeze(None);
        let result = memory::patch(self.target as *mut u8, &self.orig[..self.stolen]);
        threads::thaw(frozen);
        result?;
        self.enabled = false;
        Ok(())
    }

    /// The trampoline, i.e. where the original function can still be called.
    pub fn trampoline(&self) -> *const c_void {
        self.tramp as *const c_void
    }

    /// The trampoline as a typed function pointer.
    ///
    /// # Panics
    /// If `F` is not pointer sized.
    pub fn function<F: Copy>(&self) -> F {
        assert_eq!(
            std::mem::size_of::<F>(),
            std::mem::size_of::<*const c_void>(),
            "not a function pointer"
        );
        unsafe { std::mem::transmute_copy(&self.tramp) }
    }

    /// Address that was hooked.
    pub fn target(&self) -> *mut c_void {
        self.target
    }

    /// Address that now receives the calls.
    pub fn detour(&self) -> *mut c_void {
        self.detour
    }

    /// Number of relocated prologue bytes.
    pub fn stolen_len(&self) -> usize {
        self.stolen
    }

    /// Whether the patch is currently in place.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Drop for Hook {
    fn drop(&mut self) {
        unsafe {
            let _ = self.disable();
        }
    }
}

/// `jmp qword ptr [rip+0]` followed by the absolute address (14 bytes).
unsafe fn write_abs_jump(at: *mut u8, dest: usize) -> usize {
    let mut stub = [0u8; 14];
    stub[..6].copy_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    stub[6..].copy_from_slice(&(dest as u64).to_le_bytes());
    std::ptr::copy_nonoverlapping(stub.as_ptr(), at, 14);
    14
}

/// Copy one instruction to `dst`, fixing up anything address dependent.
/// Returns how many bytes were written.
unsafe fn relocate(insn: &Insn, code: &[u8], orig: usize, dst: usize) -> Result<usize, Error> {
    let bytes = &code[..insn.len];
    let mut out = [0u8; 16];

    let written = match insn.rel {
        // no near form exists, so the instruction cannot survive a move
        Some(Rel::Loop8) => return Err(Error::Relocation),

        // short branch: promote to the near form so the destination stays in
        // reach from the trampoline
        Some(Rel::Jmp8) | Some(Rel::Jcc8(_)) => {
            let step = bytes[insn.disp_off] as i8 as i64;
            let dest = (orig as i64 + insn.len as i64 + step) as usize;
            let conditional = matches!(insn.rel, Some(Rel::Jcc8(_)));
            let len = if conditional { 6 } else { 5 };
            let delta = dest as i64 - (dst as i64 + len as i64);
            let disp = i32::try_from(delta).map_err(|_| Error::Relocation)?;
            match insn.rel {
                Some(Rel::Jcc8(cc)) => {
                    out[0] = 0x0F;
                    out[1] = 0x80 | cc;
                    out[2..6].copy_from_slice(&disp.to_le_bytes());
                }
                _ => {
                    out[0] = 0xE9;
                    out[1..5].copy_from_slice(&disp.to_le_bytes());
                }
            }
            len
        }

        // near branch: same encoding, new displacement
        Some(Rel::Jmp32) | Some(Rel::Call32) | Some(Rel::Jcc32(_)) => {
            out[..insn.len].copy_from_slice(bytes);
            let step = i32::from_le_bytes(bytes[insn.disp_off..insn.disp_off + 4].try_into().unwrap());
            let dest = (orig as i64 + insn.len as i64 + step as i64) as usize;
            let delta = dest as i64 - (dst as i64 + insn.len as i64);
            let disp = i32::try_from(delta).map_err(|_| Error::Relocation)?;
            out[insn.disp_off..insn.disp_off + 4].copy_from_slice(&disp.to_le_bytes());
            insn.len
        }

        None => {
            out[..insn.len].copy_from_slice(bytes);
            if let Some(off) = insn.rip_off {
                let step = i32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()) as i64;
                let delta = step + (orig as i64 - dst as i64);
                let disp = i32::try_from(delta).map_err(|_| Error::Relocation)?;
                out[off..off + 4].copy_from_slice(&disp.to_le_bytes());
            }
            insn.len
        }
    };

    std::ptr::copy_nonoverlapping(out.as_ptr(), dst as *mut u8, written);
    Ok(written)
}
