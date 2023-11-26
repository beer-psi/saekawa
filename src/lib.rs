mod configuration;
mod handlers;
mod helpers;
mod icf;
mod log;
mod saekawa;
mod types;

use std::ffi::c_void;
use std::{ptr, thread};

use ::log::{error, warn};
use lazy_static::lazy_static;
use url::Url;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE, FALSE};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{DuplicateHandle, CloseHandle};
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentThread};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, SYNCHRONIZE};

use crate::configuration::Configuration;
use crate::helpers::hash_endpoint;
use crate::log::Logger;
use crate::saekawa::{hook_init, hook_release};

lazy_static! {
    pub static ref CONFIGURATION: Configuration = {
        let result = Configuration::load();
        if let Err(err) = result {
            error!("{:#}", err);
            std::process::exit(1);
        }

        result.unwrap()
    };
    pub static ref TACHI_STATUS_URL: String = {
        let result = Url::parse(&CONFIGURATION.tachi.base_url)
            .and_then(|url| url.join(&CONFIGURATION.tachi.status));
        if let Err(err) = result {
            error!("Could not parse Tachi status URL: {:#}", err);
            std::process::exit(1);
        }

        result.unwrap().to_string()
    };
    pub static ref TACHI_IMPORT_URL: String = {
        let result = Url::parse(&CONFIGURATION.tachi.base_url)
            .and_then(|url| url.join(&CONFIGURATION.tachi.import));
        if let Err(err) = result {
            error!("Could not parse Tachi import URL: {:#}", err);
            std::process::exit(1);
        }

        result.unwrap().to_string()
    };
    pub static ref UPSERT_USER_ALL_API_ENCRYPTED: Option<String> =
        hash_endpoint("UpsertUserAllApi");
    pub static ref GET_USER_MUSIC_API_ENCRYPTED: Option<String> = hash_endpoint("GetUserMusicApi");
}

fn init_logger() {
    env_logger::builder()
        .filter_level(::log::LevelFilter::Error)
        .filter_module(
            "saekawa",
            if cfg!(debug_assertions) {
                ::log::LevelFilter::Debug
            } else {
                ::log::LevelFilter::Info
            },
        )
        .parse_default_env()
        .target(env_logger::Target::Pipe(Box::new(Logger::new())))
        .format(|f, record| {
            use crate::log::{colored_level, max_target_width, Padded};
            use std::io::Write;

            let target = record.target();
            let max_width = max_target_width(target);

            let mut style = f.style();
            let level = colored_level(&mut style, record.level());

            let mut style = f.style();
            let target = style.set_bold(true).value(Padded {
                value: target,
                width: max_width,
            });

            let time = chrono::Local::now().format("%d/%m/%Y %H:%M:%S");

            writeln!(f, "[{}] {} {} -> {}", time, level, target, record.args())
        })
        .init();
}

struct ThreadHandle(*mut c_void);

impl ThreadHandle {
    pub unsafe fn wait_and_close(self, ms: u32) {
        WaitForSingleObject(self.0, ms);
        CloseHandle(self.0);
    }
}

unsafe impl Send for ThreadHandle {}
unsafe impl Sync for ThreadHandle {}

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            init_logger();

            let (cur_thread, result) = unsafe {
                let mut cur_thread = ptr::null_mut();
                let result = DuplicateHandle(
                    GetCurrentProcess(),
                    GetCurrentThread(),
                    GetCurrentProcess(),
                    &mut cur_thread,
                    SYNCHRONIZE,
                    FALSE,
                    0
                );

                if result == 0 {
                    warn!("Failed to get current thread handle, error code: {}", GetLastError());
                }

                (ThreadHandle(cur_thread), result)
            };

            thread::spawn(move || {
                if result != 0 {
                    unsafe { cur_thread.wait_and_close(100) };
                }
    
                if let Err(err) = hook_init() {
                    error!("Failed to initialize hook: {:#}", err);
                }
            });
        }
        DLL_PROCESS_DETACH => {
            if let Err(err) = hook_release() {
                error!("{:#}", err);
                return FALSE;
            }
        }
        _ => {}
    }

    TRUE
}
