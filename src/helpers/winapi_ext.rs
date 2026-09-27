use std::{mem::MaybeUninit, ptr};

use snafu::prelude::Snafu;
use widestring::U16CString;
use winapi::{
    shared::{
        minwindef::{FALSE, HINSTANCE, HMODULE},
        ntdef::HANDLE,
        winerror::ERROR_INSUFFICIENT_BUFFER,
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::{CloseHandle, DuplicateHandle},
        libloaderapi::{FreeLibraryAndExitThread, GetModuleFileNameW},
        processthreadsapi::{GetCurrentProcess, GetCurrentThread},
        profileapi::{QueryPerformanceCounter, QueryPerformanceFrequency},
        synchapi::WaitForSingleObject,
        winnt::{LARGE_INTEGER, SYNCHRONIZE},
    },
};

pub struct ThreadHandle(HANDLE);

unsafe impl Send for ThreadHandle {}
unsafe impl Sync for ThreadHandle {}
impl ThreadHandle {
    pub fn duplicate_thread_handle() -> Result<Self, u32> {
        unsafe {
            let mut cur_thread = ptr::null_mut();
            let result = DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentThread(),
                GetCurrentProcess(),
                &mut cur_thread,
                SYNCHRONIZE,
                FALSE,
                0,
            );

            if result == 0 {
                return Err(GetLastError());
            }

            Ok(ThreadHandle(cur_thread as HANDLE))
        }
    }

    pub fn wait_and_close(self, ms: u32) {
        unsafe {
            WaitForSingleObject(self.0, ms);
            CloseHandle(self.0);
        }
    }
}

#[cfg_attr(not(feature = "autoupdate"), allow(dead_code))]
pub struct LibraryHandle(HINSTANCE);

unsafe impl Send for LibraryHandle {}
unsafe impl Sync for LibraryHandle {}
impl LibraryHandle {
    pub unsafe fn new(handle: HINSTANCE) -> Self {
        Self(handle)
    }

    #[cfg_attr(not(feature = "autoupdate"), allow(dead_code))]
    pub fn handle(&self) -> HINSTANCE {
        self.0
    }

    #[cfg_attr(not(feature = "autoupdate"), allow(dead_code))]
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

        if !is_success(result) {
            let errno = unsafe { GetLastError() };

            return Err(ReadStringFnError::Other { errno });
        }

        let out = U16CString::from_vec_truncate(&buffer[..buffer_length as usize]);

        return out.to_string().map_err(|_| ReadStringFnError::InvalidData);
    }

    Err(ReadStringFnError::Other { errno })
}

#[cfg_attr(not(feature = "autoupdate"), allow(dead_code))]
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

const NANOS_PER_SEC: u64 = 1_000_000_000;

// https://github.com/rust-lang/rust/blob/feaadeeaca7db0594da854e7c8c07495341c7439/library/std/src/sys/helpers/mod.rs#L23-L34
/// Computes `(value*numerator)/denom` without overflow, as long as both
/// `numerator*denom` and the overall result fit into `u64` (which is the case
/// for our time conversions).
#[cfg_attr(not(target_os = "windows"), allow(unused))] // Not used on all platforms.
pub fn mul_div_u64(value: u64, numerator: u64, denom: u64) -> u64 {
    let q = value / denom;
    let r = value % denom;
    // Decompose value as (value/denom*denom + value%denom),
    // substitute into (value*numerator)/denom and simplify.
    // r < denom, so (denom*numerator) is the upper bound of (r*numerator)
    q * numerator + r * numerator / denom
}

// https://github.com/rust-lang/rust/blob/feaadeeaca7db0594da854e7c8c07495341c7439/library/std/src/sys/time/windows.rs#L29-L47
pub fn perf_counter_ns() -> u64 {
    let freq = unsafe {
        let mut freq: MaybeUninit<LARGE_INTEGER> = MaybeUninit::uninit();

        QueryPerformanceFrequency(freq.as_mut_ptr());
        *freq.assume_init().QuadPart()
    };
    let now = unsafe {
        let mut now: MaybeUninit<LARGE_INTEGER> = MaybeUninit::uninit();

        QueryPerformanceCounter(now.as_mut_ptr());
        *now.assume_init().QuadPart()
    };
    let instant_nsec = mul_div_u64(now as u64, NANOS_PER_SEC, freq as u64);
    let instant_nsec = instant_nsec + (u64::MAX / 4);

    instant_nsec
}
