#![cfg(windows)]
mod config;
mod consts;
mod helpers;
mod logging;
mod saekawa;
mod score_import;
mod sigscan;
mod types;
mod updater;

use std::thread;

use log::{error, info, warn};
use winapi::{
    shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE},
    um::winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
};

use crate::{
    consts::{CRATE_NAME, CRATE_VERSION, GIT_BRANCH, GIT_SHA},
    helpers::winapi_ext::{LibraryHandle, ThreadHandle},
    logging::init_logger,
    saekawa::{hook_init, hook_release},
};

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            init_logger();

            let library_handle = unsafe { LibraryHandle::new(dll_module) };
            let thread_handle = ThreadHandle::duplicate_thread_handle();

            thread::spawn(move || {
                if let Ok(h) = thread_handle {
                    h.wait_and_close(1000);
                }

                info!(
                    "{} {} ({}@{}) starting up...",
                    CRATE_NAME,
                    CRATE_VERSION,
                    &GIT_SHA[0..7],
                    GIT_BRANCH,
                );

                if let Err(e) = hook_init(library_handle) {
                    error!("Failed to initialize hook: {e:#}");
                }
            });
        }
        DLL_PROCESS_DETACH => {
            if let Err(e) = hook_release() {
                warn!("Failed to release hook: {e:#}")
            }
        }
        _ => {}
    }

    TRUE
}
