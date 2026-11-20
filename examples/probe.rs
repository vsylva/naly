//! Diagnostic probe: prints the bytes `naly` works with.

use std::ffi::c_void;

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "system" fn probe_mul(a: i32, b: i32) -> i32 {
    a.wrapping_mul(b).wrapping_add(1)
}

unsafe extern "system" fn probe_detour(a: i32, b: i32) -> i32 {
    a.wrapping_mul(b).wrapping_add(2)
}

fn hex(ptr: *const u8, n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        s.push_str(&format!("{:02X} ", unsafe { *ptr.add(i) }));
    }
    s
}

fn main() {
    unsafe {
        println!("target  = {:p}", probe_mul as *const u8);
        println!("detour  = {:p}", probe_detour as *const u8);
        println!("prologue: {}", hex(probe_mul as *const u8, 16));

        let hook = match naly::Hook::prepare(probe_mul as *mut c_void, probe_detour as *mut c_void) {
            Ok(h) => h,
            Err(e) => {
                println!("prepare failed: {e}");
                return;
            }
        };
        println!("stolen  = {}", hook.stolen_len());
        println!("tramp   = {:p}", hook.trampoline());
        println!("tramp bytes: {}", hex(hook.trampoline() as *const u8, 48));
        println!("call before enable = {}", probe_mul(6, 7));
        let mut hook = hook;
        match hook.enable() {
            Ok(()) => println!("enabled"),
            Err(e) => {
                println!("enable failed: {e}");
                return;
            }
        }
        println!("patched prologue: {}", hex(probe_mul as *const u8, 16));
        println!("call while enabled = {}", probe_mul(6, 7));
        let _ = hook.disable();
        println!("call after disable = {}", probe_mul(6, 7));
    }
}
