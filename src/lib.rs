mod config;
mod helpers;
mod logging;
mod saekawa;
mod score_import;
mod sigscan;
mod types;
mod updater;

use std::thread;

use helpers::winapi_ext::ThreadHandle;
use log::{error, info, warn};
use winapi::{
    shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE},
    um::winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
};

use crate::{
    helpers::winapi_ext::LibraryHandle,
    logging::init_logger,
    saekawa::{hook_init, hook_release},
    updater::self_update,
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
                    "saekawa {} ({}@{}) starting up...",
                    env!("CARGO_PKG_VERSION"),
                    &env!("VERGEN_GIT_SHA")[0..7],
                    env!("VERGEN_GIT_BRANCH"),
                );

                match self_update(&library_handle) {
                    Ok(should_reboot) => {
                        if should_reboot {
                            info!("Self-update successful. Reloading into new hook...");
                            library_handle.free_and_exit_thread(1);
                        }
                    }
                    Err(e) => {
                        error!("Self-update failed: {e:#}");
                    }
                }

                if let Err(e) = hook_init() {
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
