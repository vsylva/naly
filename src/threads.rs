//! Freezing the process while code is rewritten.
//!
//! The patch is a handful of bytes, but another thread may be parked in the
//! middle of the instructions being replaced. Freezing first and re-pointing
//! such a thread at the equivalent spot in the trampoline keeps it from
//! resuming into half an instruction.

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::{
        Diagnostics::{
            Debug::{CONTEXT, CONTEXT_FLAGS, GetThreadContext, SetThreadContext},
            ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next},
        },
        Threading::{
            GetCurrentProcessId, GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_ACCESS_RIGHTS,
            THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
        },
    },
};

#[cfg(target_arch = "x86_64")]
const CONTEXT_CONTROL: u32 = 0x0010_0001;
#[cfg(target_arch = "x86")]
const CONTEXT_CONTROL: u32 = 0x0001_0001;

#[cfg(target_arch = "x86_64")]
unsafe fn ip_of(ctx: &CONTEXT) -> usize {
    ctx.Rip as usize
}
#[cfg(target_arch = "x86")]
unsafe fn ip_of(ctx: &CONTEXT) -> usize {
    ctx.Eip as usize
}
#[cfg(target_arch = "x86_64")]
unsafe fn set_ip(ctx: &mut CONTEXT, ip: usize) {
    ctx.Rip = ip as u64;
}
#[cfg(target_arch = "x86")]
unsafe fn set_ip(ctx: &mut CONTEXT, ip: usize) {
    ctx.Eip = ip as u32;
}

/// Where a frozen thread's instruction pointer should move to.
pub(crate) struct Fix<'a> {
    pub(crate) target: usize,
    pub(crate) len: usize,
    pub(crate) tramp: usize,
    /// `(offset in the stolen prologue, offset in the trampoline)`
    pub(crate) map: &'a [(u32, u32)],
}

pub(crate) struct Frozen {
    handles: Vec<HANDLE>,
}

unsafe fn redirect(thread: HANDLE, fix: &Fix<'_>) {
    let mut ctx: CONTEXT = std::mem::zeroed();
    ctx.ContextFlags = CONTEXT_FLAGS(CONTEXT_CONTROL);
    if GetThreadContext(thread, &mut ctx).is_err() {
        return;
    }
    let ip = ip_of(&ctx);
    if ip < fix.target || ip >= fix.target + fix.len {
        return;
    }
    let offset = (ip - fix.target) as u32;
    if let Some(&(_, to)) = fix.map.iter().find(|(from, _)| *from == offset) {
        set_ip(&mut ctx, fix.tramp + to as usize);
        let _ = SetThreadContext(thread, &ctx);
    }
}

/// Suspend every other thread of this process.
///
/// The thread list is collected before the first suspension so nothing
/// allocates while threads are stopped — a stopped thread can be holding the
/// allocator lock.
pub(crate) unsafe fn freeze(fix: Option<&Fix<'_>>) -> Frozen {
    let mut ids: Vec<u32> = Vec::new();
    if let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
        let me = GetCurrentThreadId();
        let pid = GetCurrentProcessId();
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snapshot, &mut entry).is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid && entry.th32ThreadID != me {
                    ids.push(entry.th32ThreadID);
                }
                if Thread32Next(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }

    let access = THREAD_ACCESS_RIGHTS(THREAD_SUSPEND_RESUME.0 | THREAD_GET_CONTEXT.0 | THREAD_SET_CONTEXT.0);
    let mut handles: Vec<HANDLE> = Vec::with_capacity(ids.len());
    for id in ids {
        let Ok(thread) = OpenThread(access, false, id) else {
            continue;
        };
        if SuspendThread(thread) == u32::MAX {
            let _ = CloseHandle(thread);
            continue;
        }
        if let Some(fix) = fix {
            redirect(thread, fix);
        }
        handles.push(thread);
    }
    Frozen { handles }
}

pub(crate) unsafe fn thaw(frozen: Frozen) {
    for thread in frozen.handles {
        let _ = ResumeThread(thread);
        let _ = CloseHandle(thread);
    }
}
