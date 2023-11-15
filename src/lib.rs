mod configuration;
mod helpers;
mod log;
mod saekawa;
mod types;

use ::log::error;
use lazy_static::lazy_static;
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;
use url::Url;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE};
use winapi::um::winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

use crate::configuration::Configuration;
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
    pub static ref UPSERT_USER_ALL_API_ENCRYPTED: String = {
        if CONFIGURATION.crypto.salt.is_empty() {
            // return a bullshit value
            return "ffffffffffffffffffffffffffffffff".to_string();
        }

        let salt = match hex::decode(&CONFIGURATION.crypto.salt) {
            Ok(salt) => salt,
            Err(err) => {
                error!("Could not parse salt as hex string: {:#}", err);
                std::process::exit(1);
            }
        };

        let key = pbkdf2_hmac_array::<Sha1, 16>(
            b"UpsertUserAllApi",
            &salt,
            CONFIGURATION.crypto.iterations
        );

        hex::encode(key)
    };
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

#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => {
            init_logger();

            if let Err(err) = hook_init() {
                error!("{:#}", err);
            }
        }
        DLL_PROCESS_DETACH => {
            if let Err(err) = hook_release() {
                error!("{:#}", err);
            }
        }
        _ => {}
    }

    TRUE
}
