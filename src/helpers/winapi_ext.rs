use snafu::prelude::Snafu;
use widestring::U16CString;
use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{HINSTANCE, HMODULE, TRUE},
        winerror::ERROR_INSUFFICIENT_BUFFER,
    },
    um::{
        errhandlingapi::GetLastError,
        libloaderapi::{FreeLibraryAndExitThread, GetModuleFileNameW},
        winhttp::{WinHttpQueryOption, HINTERNET},
    },
};

pub struct LibraryHandle(HINSTANCE);

unsafe impl Send for LibraryHandle {}
unsafe impl Sync for LibraryHandle {}
impl LibraryHandle {
    pub unsafe fn new(handle: HINSTANCE) -> Self {
        Self(handle)
    }

    pub fn handle(&self) -> HINSTANCE {
        self.0
    }

    pub fn free_and_exit_thread(self, code: u32) -> ! {
        unsafe {
            FreeLibraryAndExitThread(self.0, code);
        }
        unreachable!()
    }
}

#[derive(Debug, Snafu)]
pub enum ReadStringFnError {
    InvalidData,
    Other { errno: u32 },
}

pub fn read_string_from_function_call(
    reader: impl Fn(&mut [u16], &mut u32) -> i32,
    is_success: impl Fn(i32) -> bool,
) -> Result<String, ReadStringFnError> {
    let mut buffer = vec![0u16; 255];
    let mut buffer_length = 255;
    let result = reader(&mut buffer, &mut buffer_length);

    if is_success(result) {
        let out = U16CString::from_vec_truncate(&buffer[..buffer_length as usize]);

        return out.to_string().map_err(|_| ReadStringFnError::InvalidData);
    }

    let errno = unsafe { GetLastError() };

    if errno == ERROR_INSUFFICIENT_BUFFER {
        buffer.resize(buffer_length as usize, 0);
        let result = reader(&mut buffer, &mut buffer_length);

        if result != TRUE {
            let errno = unsafe { GetLastError() };

            return Err(ReadStringFnError::Other { errno });
        }

        let out = U16CString::from_vec_truncate(&buffer[..buffer_length as usize]);

        return out.to_string().map_err(|_| ReadStringFnError::InvalidData);
    }

    Err(ReadStringFnError::Other { errno })
}

pub fn winhttp_query_option(handle: HINTERNET, option: u32) -> Result<String, ReadStringFnError> {
    read_string_from_function_call(
        |buf, buflen| unsafe {
            WinHttpQueryOption(handle, option, buf.as_mut_ptr() as *mut c_void, buflen)
        },
        |ret| ret == TRUE,
    )
}

pub fn get_module_file_name(handle: HMODULE) -> Result<String, ReadStringFnError> {
    read_string_from_function_call(
        |buf, buflen| unsafe {
            let ret = GetModuleFileNameW(handle, buf.as_mut_ptr(), *buflen) as i32;

            if GetLastError() == ERROR_INSUFFICIENT_BUFFER {
                *buflen = 32767;
            }

            ret
        },
        |_| unsafe { GetLastError() != ERROR_INSUFFICIENT_BUFFER },
    )
}
