## naly

```rust
use naly::Hook;

type Add = unsafe extern "system" fn(i32, i32) -> i32;

static ORIGINAL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

unsafe extern "system" fn detour(a: i32, b: i32) -> i32 {
    let original: Add = std::mem::transmute(ORIGINAL.load(std::sync::atomic::Ordering::Acquire));
    original(a, b) + 1
}

unsafe fn install(target: Add) -> naly::Hook {
    let hook = Hook::attach(target as *mut std::ffi::c_void, detour as *mut std::ffi::c_void).unwrap();
    ORIGINAL.store(hook.trampoline() as usize, std::sync::atomic::Ordering::Release);
    hook
}
```

* `Hook::attach` — patch immediately, returning the armed hook.
* `Hook::prepare` — build the trampoline first, arm later (needed when the
  detour calls back through the trampoline).
* `enable` / `disable` — flip the patch, reversible as often as you like.
* `trampoline` / `function::<F>()` — the original function.
* `Drop` — unpatch and free.

### Limits

* Windows x86 / x86-64 only; no ARM.
* Hooks must start on real instructions — patching the middle of one is not
  detected.
* A trampoline is freed on drop, so it is unsafe to drop a hook while another
  thread is still executing inside its trampoline.
* `naly` does not bypass anti-cheat or integrity checks; it patches code and
  leaves evidence (bytes, an executable private page, a suspended-thread window).

### Test

```bash
cargo test                       # x86-64
cargo test --target i686-pc-windows-msvc
```
