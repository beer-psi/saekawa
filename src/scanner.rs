use std::{
    ffi::c_void,
    mem::{self, offset_of, MaybeUninit},
    ptr, slice,
};

use log::debug;
use snafu::Snafu;
use winapi::{
    shared::{minwindef::MAX_PATH, winerror::ERROR_INSUFFICIENT_BUFFER},
    um::{
        errhandlingapi::GetLastError,
        fileapi::{CreateFileW, OPEN_EXISTING},
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        libloaderapi::{GetModuleFileNameW, GetModuleHandleW},
        memoryapi::{CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_COPY},
        processthreadsapi::GetCurrentProcess,
        psapi::{GetModuleInformation, MODULEINFO},
        winnt::{
            FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, GENERIC_READ, IMAGE_DOS_HEADER,
            IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER, PAGE_READONLY, SEC_IMAGE,
        },
    },
};

pub struct Scanner {
    scan_mode: lightningscanner::ScanMode,

    module_copy: Vec<u8>,
    module_base: usize,

    text_section_offset: usize,
    text_section_size: usize,
}

#[derive(Debug, Snafu)]
pub enum ScannerError {
    #[snafu(display("Win32 error: {error}"))]
    Win32Error { error: u32 },

    #[snafu(display("base module does not have a .text section"))]
    NoTextSection,
}

impl Scanner {
    pub fn new() -> Result<Self, ScannerError> {
        let scan_mode = if is_x86_feature_detected!("avx2") {
            lightningscanner::ScanMode::Avx2
        } else if is_x86_feature_detected!("sse4.2") {
            lightningscanner::ScanMode::Sse42
        } else {
            lightningscanner::ScanMode::Scalar
        };

        let mut module_info: MaybeUninit<MODULEINFO> = MaybeUninit::uninit();
        let hmodule = unsafe { GetModuleHandleW(ptr::null_mut()) };
        let result = unsafe {
            GetModuleInformation(
                GetCurrentProcess(),
                hmodule,
                module_info.as_mut_ptr(),
                mem::size_of::<MODULEINFO>() as u32,
            )
        };

        if result == 0 {
            return Err(ScannerError::Win32Error {
                error: unsafe { GetLastError() },
            });
        }

        let module_info = unsafe { module_info.assume_init() };

        debug!(
            "lpBaseOfDll={:p} SizeOfImage={} EntryPoint={:p}",
            module_info.lpBaseOfDll, module_info.SizeOfImage, module_info.EntryPoint
        );

        let mut text_section_offset: usize = 0;
        let mut text_section_size: usize = 0;

        unsafe {
            let dos_header = module_info.lpBaseOfDll.cast::<IMAGE_DOS_HEADER>();
            let nt_header = module_info
                .lpBaseOfDll
                .byte_offset((*dos_header).e_lfanew as isize)
                .cast::<IMAGE_NT_HEADERS>();
            let section_headers = nt_header
                .byte_add(offset_of!(IMAGE_NT_HEADERS, OptionalHeader))
                .byte_add((*nt_header).FileHeader.SizeOfOptionalHeader as usize)
                .cast::<IMAGE_SECTION_HEADER>();
            let section_headers = slice::from_raw_parts(
                section_headers,
                (*nt_header).FileHeader.NumberOfSections as usize,
            );

            for section_header in section_headers {
                if section_header.Name == *b".text\0\0\0" {
                    text_section_offset = section_header.VirtualAddress as usize;
                    text_section_size = *section_header.Misc.VirtualSize() as usize;
                    break;
                }
            }
        }

        if text_section_size == 0 {
            return Err(ScannerError::NoTextSection);
        }

        debug!(".text offset={text_section_offset} size={text_section_size}");

        let module_copy = unsafe {
            let mut module_file_name = vec![0u16; MAX_PATH];

            loop {
                let result = GetModuleFileNameW(
                    hmodule,
                    module_file_name.as_mut_ptr(),
                    module_file_name.len() as u32,
                ) as usize;
                let err = GetLastError();

                if result == 0 {
                    return Err(ScannerError::Win32Error { error: err });
                }

                if err == ERROR_INSUFFICIENT_BUFFER {
                    module_file_name.resize(module_file_name.len() * 2, 0);
                    continue;
                }

                break;
            }

            let hfile = CreateFileW(
                module_file_name.as_ptr() as *const _,
                GENERIC_READ,
                FILE_SHARE_READ,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );

            if hfile == INVALID_HANDLE_VALUE || hfile.is_null() {
                return Err(ScannerError::Win32Error {
                    error: GetLastError(),
                });
            }

            let mapping = CreateFileMappingW(
                hfile,
                ptr::null_mut(),
                PAGE_READONLY | SEC_IMAGE,
                0,
                0,
                ptr::null(),
            );

            if mapping.is_null() {
                return Err(ScannerError::Win32Error {
                    error: GetLastError(),
                });
            }

            let view = MapViewOfFile(mapping, FILE_MAP_COPY, 0, 0, 0);

            if view.is_null() {
                return Err(ScannerError::Win32Error {
                    error: GetLastError(),
                });
            }

            let copy = Vec::from(slice::from_raw_parts(
                view.cast::<u8>(),
                module_info.SizeOfImage as usize,
            ));

            UnmapViewOfFile(view);
            CloseHandle(mapping);
            CloseHandle(hfile);

            copy
        };

        Ok(Self {
            scan_mode,
            module_copy,
            module_base: module_info.lpBaseOfDll.addr(),
            text_section_offset,
            text_section_size,
        })
    }

    pub fn scan_text(&self, signature: &'static str) -> Option<*const c_void> {
        let scanner = lightningscanner::Scanner::new(signature);
        let copy_base = self.module_copy.as_ptr();
        let result = unsafe {
            scanner.find(
                Some(self.scan_mode),
                copy_base.byte_add(self.text_section_offset),
                self.text_section_size,
            )
        };

        if !result.is_valid() {
            return None;
        }

        let address = result.get_addr();
        let b = unsafe { *address };

        // convert E8/E9 ?? ?? ?? ?? signature into their CALL/JMP targets
        let address = if b == 0xE8 || b == 0xE9 {
            unsafe {
                let rel = i32::from_le_bytes(
                    std::slice::from_raw_parts(address.byte_add(1), 4)
                        .try_into()
                        .expect("std::slice::from_raw_parts with len=4 should convert to [u8; 4]"),
                );

                address.add(5).offset(rel as isize)
            }
        } else {
            address
        };

        // convert the address onto the actual module
        let address = unsafe {
            ptr::without_provenance::<c_void>(self.module_base)
                .byte_offset(address.byte_offset_from(copy_base))
        };

        // debug!("{signature}: {address:p}");

        Some(address)
    }
}
