use std::ptr;

use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{BOOL, DWORD, HMODULE, LPVOID, PROC},
        ntdef::{HANDLE, LPCWSTR, LPSTR},
    },
};

#[link_section = ".rtext"]
#[used]
pub static mut GET_MODULE_FILE_NAME_A_PTR: PROC = ptr::null_mut();

#[link_section = ".rtext"]
#[used]
pub static mut GET_PROCESS_HEAP_PTR: PROC = ptr::null_mut();

#[link_section = ".rtext"]
#[used]
pub static mut REPLCE_FILE_W_PTR: PROC = ptr::null_mut();

#[link_section = ".rtext"]
#[used]
pub static mut LOAD_LIBRARY_W_POINTER: PROC = ptr::null_mut();

#[link_section = ".rtext"]
#[used]
pub static mut HEAP_FREE_PTR: PROC = ptr::null_mut();

#[link_section = ".rtext"]
#[used]
pub static mut SLEEP_PTR: PROC = ptr::null_mut();

#[link_section = ".rtext"]
#[used]
pub static mut GET_LAST_ERROR_PTR: PROC = ptr::null_mut();

type GetModuleFileNameAFn = unsafe extern "system" fn(HMODULE, LPSTR, DWORD) -> DWORD;
type GetProcessHeapFn = unsafe extern "system" fn() -> HANDLE;
type ReplaceFileWFn =
    unsafe extern "system" fn(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID) -> BOOL;
type LoadLibraryWFn = unsafe extern "system" fn(LPCWSTR) -> HMODULE;
type HeapFreeFn = unsafe extern "system" fn(HANDLE, DWORD, LPVOID) -> BOOL;
type SleepFn = unsafe extern "system" fn(DWORD);

#[repr(C)]
pub struct ReplaceArgs {
    pub module: HMODULE,
    pub old: [u16; 32767],
    pub new: [u16; 32767],
}

/// SAFETY: This function *must* only be called when the addresses for the function have been filled in.
#[allow(non_snake_case)]
#[link_section = ".rtext"]
pub unsafe extern "system" fn replace_with_new_library(parameter: *const c_void) -> u32 {
    let args = parameter as *const ReplaceArgs;
    let GetModuleFileNameA =
        std::mem::transmute::<PROC, GetModuleFileNameAFn>(GET_MODULE_FILE_NAME_A_PTR);
    let GetProcessHeap = std::mem::transmute::<PROC, GetProcessHeapFn>(GET_PROCESS_HEAP_PTR);
    let ReplaceFileW = std::mem::transmute::<PROC, ReplaceFileWFn>(REPLCE_FILE_W_PTR);
    let LoadLibraryW = std::mem::transmute::<PROC, LoadLibraryWFn>(LOAD_LIBRARY_W_POINTER);
    let HeapFree = std::mem::transmute::<PROC, HeapFreeFn>(HEAP_FREE_PTR);
    let Sleep = std::mem::transmute::<PROC, SleepFn>(SLEEP_PTR);

    // Wait for the old library to be freed
    let mut filename = 0;

    loop {
        let result = GetModuleFileNameA((*args).module, &mut filename, 1);

        if result == 0 {
            break;
        }

        Sleep(1000);
    }

    let result = ReplaceFileW(
        (*args).old.as_ptr(),
        (*args).new.as_ptr(),
        ptr::null(),
        2,
        ptr::null_mut(),
        ptr::null_mut(),
    );

    if result > 0 {
        LoadLibraryW((*args).old.as_ptr());
    } else {
        LoadLibraryW((*args).new.as_ptr());
    }

    HeapFree(GetProcessHeap(), 0, args as *mut _) as u32
}
