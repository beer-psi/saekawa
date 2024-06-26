use std::{ffi::CString, fs::File, io::Write};

use winapi::um::{debugapi::OutputDebugStringA, wincon::GetConsoleWindow};

#[derive(Debug)]
struct Logger {
    file: File,
    has_console_output: bool,
}

impl Logger {
    pub fn new() -> Self {
        Self {
            file: File::create("saekawa.log").unwrap(),
            has_console_output: unsafe { !GetConsoleWindow().is_null() },
        }
    }
}

impl Write for Logger {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.has_console_output {
            let _ = std::io::stdout().write(buf);
        } else if let Ok(c_str) = CString::new(buf) {
            unsafe {
                OutputDebugStringA(c_str.as_ptr());
            }
        }

        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Ignore the result of the write to stdout, since it's not really important
        let _ = std::io::stdout().flush();
        self.file.flush()
    }
}

pub fn init_logger() {
    env_logger::builder()
        .filter_module(
            "saekawa",
            if cfg!(debug_assertions) {
                log::LevelFilter::Debug
            } else {
                log::LevelFilter::Info
            },
        )
        .parse_default_env()
        .target(env_logger::Target::Pipe(Box::new(Logger::new())))
        .format(|f, record| {
            let target = record.target();
            let level = record.level();
            let args = record.args();
            let time = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");

            writeln!(f, "{time} {level:<5} [{target}] {args}")
        })
        .init();
}
