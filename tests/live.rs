//! Live detours: our own functions plus a real kernel32 export.

use std::ffi::c_void;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

use naly::Hook;

static LOCK: Mutex<()> = Mutex::new(());
static HITS: AtomicUsize = AtomicUsize::new(0);
static ORIG: AtomicUsize = AtomicUsize::new(0);

unsafe extern "system" {
    fn GetTickCount() -> u32;
    fn GetSystemTimeAsFileTime(out: *mut u64);
}

#[inline(never)]
#[unsafe(no_mangle)]
unsafe extern "system" fn naly_mul(a: i32, b: i32) -> i32 {
    a.wrapping_mul(b).wrapping_add(1)
}

/// A second target, so two hooks can be live at the same time.
#[inline(never)]
#[unsafe(no_mangle)]
unsafe extern "system" fn naly_add(a: i32, b: i32) -> i32 {
    a.wrapping_add(b)
}

unsafe extern "system" fn detour_mul(a: i32, b: i32) -> i32 {
    HITS.fetch_add(1, SeqCst);
    let original: unsafe extern "system" fn(i32, i32) -> i32 = std::mem::transmute(ORIG.load(SeqCst));
    original(a, b) + 100
}

#[test]
fn enable_disable_roundtrip() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        assert_eq!(naly_mul(6, 7), 43);

        let mut hook = Hook::prepare(naly_mul as *mut c_void, detour_mul as *mut c_void).expect("prepare");
        assert!(hook.stolen_len() >= naly::MIN_PATCH, "stole {} bytes", hook.stolen_len());
        assert!(!hook.is_enabled());
        assert!(!hook.trampoline().is_null());
        ORIG.store(hook.trampoline() as usize, SeqCst);

        // preparing must not touch the target
        assert_eq!(naly_mul(6, 7), 43);

        hook.enable().expect("enable");
        assert!(hook.is_enabled());
        assert_eq!(naly_mul(6, 7), 143, "detour did not run");
        assert_eq!(HITS.load(SeqCst), 1);

        hook.disable().expect("disable");
        assert!(!hook.is_enabled());
        assert_eq!(naly_mul(6, 7), 43, "original bytes were not restored");

        hook.enable().expect("re-enable");
        assert_eq!(naly_mul(6, 7), 143);

        drop(hook);
        assert_eq!(naly_mul(6, 7), 43, "drop did not unpatch");
        assert_eq!(HITS.load(SeqCst), 2);
    }
}

#[test]
fn two_hooks_coexist() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    static ORIG_A: AtomicUsize = AtomicUsize::new(0);
    static ORIG_B: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn detour_a(a: i32, b: i32) -> i32 {
        let f: unsafe extern "system" fn(i32, i32) -> i32 = std::mem::transmute(ORIG_A.load(SeqCst));
        f(a, b) * 2
    }
    unsafe extern "system" fn detour_b(a: i32, b: i32) -> i32 {
        let f: unsafe extern "system" fn(i32, i32) -> i32 = std::mem::transmute(ORIG_B.load(SeqCst));
        f(a, b) - 1
    }

    unsafe {
        assert_eq!(naly_mul(3, 3), 10);
        assert_eq!(naly_add(3, 3), 6);

        let mut mul = Hook::prepare(naly_mul as *mut c_void, detour_a as *mut c_void).expect("prepare mul");
        let mut add = Hook::prepare(naly_add as *mut c_void, detour_b as *mut c_void).expect("prepare add");
        ORIG_A.store(mul.trampoline() as usize, SeqCst);
        ORIG_B.store(add.trampoline() as usize, SeqCst);
        let _ = mul.enable();
        let _ = add.enable();

        assert_eq!(naly_mul(3, 3), 20);
        assert_eq!(naly_add(3, 3), 5);
    }
}

#[test]
fn attaches_a_real_export() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe extern "system" fn fake_tick() -> u32 {
        0x600D
    }

    unsafe {
        assert_ne!(GetTickCount(), 0x600D, "the fake value must be distinguishable");
        let hook = Hook::attach(GetTickCount as *mut c_void, fake_tick as *mut c_void).expect("attach GetTickCount");
        assert_eq!(GetTickCount(), 0x600D);
        drop(hook);
        assert_ne!(GetTickCount(), 0x600D, "unpatch failed");
    }
}

#[test]
fn trampoline_is_callable_when_disabled() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let hook = Hook::prepare(naly_mul as *mut c_void, detour_mul as *mut c_void).expect("prepare");
        let original = hook.function::<unsafe extern "system" fn(i32, i32) -> i32>();
        assert_eq!(original(4, 5), 21, "trampoline must reproduce the original");
    }
}

#[test]
fn hooks_an_api_taking_a_pointer() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    static SEEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn detour_time(out: *mut u64) {
        SEEN.fetch_add(1, SeqCst);
        if !out.is_null()
        {
            out.write_unaligned(0x1122_3344_5566_7788);
        }
    }

    unsafe {
        let hook = Hook::attach(GetSystemTimeAsFileTime as *mut c_void, detour_time as *mut c_void).expect("attach");
        let mut value = 0u64;
        GetSystemTimeAsFileTime(&mut value);
        assert_eq!(value, 0x1122_3344_5566_7788);
        assert_eq!(SEEN.load(SeqCst), 1);
        drop(hook);
    }
}

#[test]
fn rejects_degenerate_input() {
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        assert!(matches!(Hook::prepare(std::ptr::null_mut(), std::ptr::dangling_mut::<c_void>()), Err(naly::Error::Null)));
        assert!(matches!(Hook::prepare(naly_mul as *mut c_void, std::ptr::null_mut()), Err(naly::Error::Null)));
    }
}
