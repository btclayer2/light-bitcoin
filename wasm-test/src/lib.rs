#![no_std]
#![feature(alloc_error_handler)]
#![allow(unused)]

use light_bitcoin::*;

/// A global allocator for WASM environment.
#[cfg(not(feature = "std"))]
#[global_allocator]
static ALLOCATOR: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// A default panic handler for WASM environment.
#[cfg(not(feature = "std"))]
#[panic_handler]
pub fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::wasm32::unreachable();
    }
}

/// A default OOM handler for WASM environment.
#[cfg(not(feature = "std"))]
#[alloc_error_handler]
pub fn oom(_: core::alloc::Layout) -> ! {
    unsafe {
        core::arch::wasm32::unreachable();
    }
}
