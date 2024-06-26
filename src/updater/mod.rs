mod external;

use std::{
    ffi::CStr,
    io::{self, Read},
    mem::{self},
    path::Path,
    ptr,
};

use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snafu::{prelude::Snafu, ResultExt};
use widestring::U16CString;
use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, HMODULE, LPVOID, PROC},
        ntdef::{LPCWSTR, LPSTR},
        winerror::{
            CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_UNTRUSTEDROOT, CRYPT_E_SECURITY_SETTINGS,
            TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE,
        },
    },
    um::{
        heapapi::HeapAlloc,
        memoryapi::{VirtualAlloc, VirtualProtect},
        minwinbase::LMEM_ZEROINIT,
        processthreadsapi::CreateThread,
        softpub::WINTRUST_ACTION_GENERIC_VERIFY_V2,
        winbase::LocalAlloc,
        wincrypt::{
            CertCloseStore, CertFindCertificateInStore, CryptMsgClose, CryptMsgGetParam,
            CryptQueryObject, CERT_FIND_SUBJECT_CERT, CERT_INFO,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
            CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_INFO_PARAM, HCERTSTORE, HCRYPTMSG,
            PCMSG_SIGNER_INFO, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        },
        winnt::{
            HANDLE, HEAP_ZERO_MEMORY, IMAGE_DOS_HEADER, IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER,
            MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
        },
        wintrust::{
            WinVerifyTrust, WINTRUST_DATA, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        },
    },
};

use self::external::{replace_with_new_library, ReplaceArgs};
use crate::helpers::winapi_ext::{get_module_file_name, LibraryHandle, ReadStringFnError};

const PUBLIC_KEY: [u8; 270] = [
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xf5, 0xbd, 0x02, 0xb0, 0x81, 0xc6, 0x4d,
    0x4c, 0xa0, 0x40, 0xa8, 0x76, 0x78, 0xe2, 0x61, 0x39, 0x13, 0x1d, 0x2f, 0x0c, 0x70, 0x71, 0x96,
    0x56, 0x67, 0xf2, 0xbe, 0xc2, 0x5c, 0xc7, 0xd4, 0xa6, 0xb5, 0x07, 0xc5, 0x7a, 0x19, 0x58, 0x10,
    0x70, 0xb5, 0x87, 0x5f, 0x3f, 0x9a, 0x78, 0x9e, 0x96, 0x5c, 0xc7, 0x88, 0x50, 0x8c, 0x34, 0xcc,
    0x51, 0xe5, 0xd5, 0xbd, 0xb8, 0xab, 0xed, 0x28, 0x7f, 0x68, 0x6e, 0x27, 0x2a, 0x1d, 0xdb, 0x9a,
    0xe9, 0x1d, 0xbc, 0xd8, 0xbf, 0xca, 0xdf, 0x65, 0xa3, 0x0a, 0x19, 0x3d, 0x00, 0x14, 0x16, 0xdd,
    0x87, 0x9f, 0xf5, 0x44, 0x9e, 0x56, 0x1e, 0xfd, 0xb5, 0xf0, 0x75, 0x3d, 0x11, 0x4c, 0x4d, 0xa5,
    0x1a, 0x24, 0xfe, 0x31, 0x77, 0xc1, 0x55, 0xf7, 0x5d, 0x9c, 0x34, 0xbe, 0x5f, 0x9d, 0x73, 0x2c,
    0x3e, 0xdb, 0x39, 0x18, 0x3c, 0xb3, 0x46, 0xe0, 0xf4, 0xa1, 0xcc, 0x2f, 0x7b, 0x07, 0xb7, 0x0e,
    0x7a, 0x92, 0x54, 0xa9, 0x9f, 0xfc, 0x4c, 0xe0, 0xbb, 0xcf, 0xba, 0x36, 0xc6, 0xcb, 0x9d, 0xb1,
    0x12, 0x4b, 0x50, 0x1c, 0x10, 0x23, 0x87, 0x28, 0x9b, 0x73, 0xe3, 0xd5, 0xc9, 0x38, 0xae, 0xd7,
    0x66, 0x73, 0x8f, 0xf8, 0x56, 0x2e, 0x48, 0x0a, 0xdb, 0x7f, 0x11, 0xbf, 0xd6, 0x4e, 0x77, 0x6c,
    0xb8, 0x12, 0xaf, 0x0b, 0x7b, 0x08, 0xe3, 0x0f, 0x7e, 0xf1, 0x6a, 0xc0, 0xac, 0x1c, 0xe2, 0x8c,
    0x47, 0xb0, 0xec, 0x10, 0xca, 0x02, 0x9c, 0x7d, 0x27, 0x78, 0x33, 0x3c, 0x25, 0x88, 0x5c, 0x4f,
    0x4b, 0xb8, 0x72, 0xeb, 0x85, 0x31, 0x39, 0xb1, 0x95, 0xae, 0xc3, 0x79, 0x38, 0x20, 0x25, 0x0e,
    0xab, 0xdc, 0x9c, 0xc8, 0x25, 0x53, 0xd2, 0xcf, 0x93, 0xf0, 0x1d, 0x95, 0x58, 0x0b, 0x0c, 0x9f,
    0xc5, 0x01, 0x7a, 0xad, 0x4f, 0x55, 0x2f, 0x24, 0xc5, 0x02, 0x03, 0x01, 0x00, 0x01,
];

// I don't know what the hell is going on with linking, but you have to link these manually,
// otherwise you end up with the addresses to the intermediary functions, which obviously
// doesn't exist once you unloads the original library.
#[link(name = "kernel32")]
extern "system" {
    pub fn GetLastError() -> u32;
    pub fn GetModuleFileNameA(hModule: HMODULE, lpFilename: LPSTR, nsize: DWORD) -> u32;
    pub fn GetProcessHeap() -> HANDLE;
    pub fn HeapFree(hHeap: HANDLE, dwFlags: DWORD, lpMem: LPVOID) -> BOOL;
    pub fn LoadLibraryW(lpFileName: LPCWSTR) -> HMODULE;
    pub fn ReplaceFileW(
        lpReplacedFileName: LPCWSTR,
        lpReplacementFileName: LPCWSTR,
        lpBackupFileName: LPCWSTR,
        dwReplaceFlags: DWORD,
        lpExclude: LPVOID,
        lpReserved: LPVOID,
    ) -> BOOL;
    pub fn Sleep(dwMilliseconds: DWORD);
}

#[derive(Debug, Snafu)]
pub enum SelfUpdateError {
    #[snafu(display("Could not get the file name of the currently running hook"))]
    FailedToGetFilename { source: ReadStringFnError },

    #[snafu(display("Invalid DOS signature"))]
    InvalidDosSignature,

    #[snafu(display("Invalid NT signature"))]
    InvalidNtSignature,

    #[snafu(display("Updater code section not found."))]
    NoUpdaterCodeSection,

    #[snafu(display("Failed to allocate memory for update"))]
    FailedToAllocateMemory,

    #[snafu(display("VirtualProtect failed with error code {errno}"))]
    FailedVirtualProtect { errno: u32 },

    #[snafu(display("Could not execute updater code: {errno}"))]
    FailedCreateThread { errno: u32 },

    #[snafu(display("Failed to request update information."))]
    FailedRequestingUpdate { source: ureq::Error },

    #[snafu(display("Invalid update information."))]
    InvalidUpdateInformation { source: io::Error },

    #[snafu(display("Could not download updated hook."))]
    FailedDownloadingUpdate { source: io::Error },

    #[snafu(display("Could not write updated hook to file."))]
    FailedWritingUpdate { source: io::Error },

    #[snafu(display("SHA-256 checksum mismatch."))]
    InvalidChecksum,

    #[snafu(display("Could not verify signature: {source:#}"))]
    InvalidSignature { source: VerifySignatureError },

    #[snafu(display("Failed to get digital signature of the update: {source:#?}"))]
    FailedGettingPubkey { source: GetSignaturePubkeyError },

    #[snafu(display("Public key mismatched."))]
    InvalidPubkey,
}

#[derive(Snafu, Debug)]
pub enum VerifySignatureError {
    #[snafu(display("Signature verification was disabled by a local policy."))]
    VerificationDisabledByPolicy,

    #[snafu(display("No signatures found."))]
    NoSignature,

    #[snafu(display("The signature was explicitly distrusted."))]
    ExplicitlyDistrusted,

    #[snafu(display("An unknown validation error occured: {errno}"))]
    Unknown { errno: i32 },
}

#[derive(Snafu, Debug)]
pub enum GetSignaturePubkeyError {
    #[snafu(display("CertQueryObject failed: {errno}"))]
    QueryObjectError { errno: u32 },

    #[snafu(display("Could not obtain size of signer information: {errno}"))]
    SignerInfoSizeError { errno: u32 },

    #[snafu(display("Could not allocate memory for signer information: {errno}"))]
    SignerInfoAllocError { errno: u32 },

    #[snafu(display("Could not obtain signer information: {errno}"))]
    SignerInfoObtainError { errno: u32 },

    #[snafu(display("Could not look up certificate in certificate store: {errno}"))]
    CertificateInStoreError { errno: u32 },

    #[snafu(display("Could not read public key."))]
    ReadPubkeyError { source: io::Error },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UpdateInformation {
    pub version: String,
    pub commit: String,
    pub sha256: String,
}

/// Checks if the hook has a newer version. Returns true if update was successful
/// and the hook should uninject itself so a newer version can load in.
pub fn self_update(module: &LibraryHandle) -> Result<bool, SelfUpdateError> {
    let agent = ureq::builder()
        .user_agent(concat!("saekawa/", env!("CARGO_PKG_VERSION")))
        .build();

    info!("Checking for updates...");
    let response = agent
        .get("https://beerpiss.github.io/saekawa/update.json")
        .call()
        .context(FailedRequestingUpdateSnafu)?
        .into_json::<UpdateInformation>()
        .context(InvalidUpdateInformationSnafu)?;

    debug!(concat!("current commit: ", env!("VERGEN_GIT_SHA")));
    debug!("remote commit: {}", response.commit);

    if response.commit == env!("VERGEN_GIT_SHA") {
        info!("Already up-to-date.");

        return Ok(false);
    }

    let module_filename =
        &get_module_file_name(module.handle()).context(FailedToGetFilenameSnafu)?;
    let module_path = Path::new(&module_filename);

    debug!("Current hook is located at {module_filename:#?}.");

    info!("Downloading update v{}...", response.version);
    let url = format!(
        "https://github.com/beerpiss/saekawa/releases/download/v{}/saekawa.dll",
        response.version
    );

    debug!("Requesting content from {url}...");
    let new_hook = {
        let mut response = agent
            .get(&url)
            .call()
            .context(FailedRequestingUpdateSnafu)?
            .into_reader();
        let mut buf = vec![];
        response
            .read_to_end(&mut buf)
            .context(FailedDownloadingUpdateSnafu)?;

        buf
    };

    debug!("Validating update contents...");
    validate_sha256(&new_hook, &response.sha256)?;

    let new_module_path = module_path.with_file_name("saekawa.new.dll");

    debug!("Writing update contents to {new_module_path:#?}...");
    std::fs::write(&new_module_path, new_hook).context(FailedWritingUpdateSnafu)?;

    debug!("Verifying digital signature...");
    let new_module_filename = new_module_path.to_string_lossy();
    verify_signature(&new_module_filename).context(InvalidSignatureSnafu)?;

    debug!("Verifying certificate public key...");
    let actual_pubkey = match get_signature_pubkey(&new_module_filename) {
        Ok(k) => k,
        Err(e) => {
            let _ = std::fs::remove_file(&new_module_path);
            return Err(SelfUpdateError::FailedGettingPubkey { source: e });
        }
    };

    if actual_pubkey != PUBLIC_KEY {
        let _ = std::fs::remove_file(&new_module_path);
        return Err(SelfUpdateError::InvalidPubkey);
    }

    debug!("Starting update sequence");
    // You know stuff is going to be cursed when the unsafe block is ~120 lines long.
    //
    // TL;DR: There's a function that waits until the current hook has been unloaded,
    // then replaces the old hook with the new hook, and loads in the new hook.
    //
    // This is achieved by linking that function alongside the required functions in a different
    // code section (".rtext"), setting references for those functions, then copying out
    // that entire section to a different memory region so it can keep executing when the
    // old hook is unloaded.
    //
    // Thanks to DJTRACKERS and their fervidex hook for the approach.
    unsafe {
        external::GET_LAST_ERROR_PTR = GetLastError as PROC;
        external::GET_MODULE_FILE_NAME_A_PTR = GetModuleFileNameA as PROC;
        external::GET_PROCESS_HEAP_PTR = GetProcessHeap as PROC;
        external::HEAP_FREE_PTR = HeapFree as PROC;
        external::LOAD_LIBRARY_W_POINTER = LoadLibraryW as PROC;
        external::REPLCE_FILE_W_PTR = ReplaceFileW as PROC;
        external::SLEEP_PTR = Sleep as PROC;

        debug!("Locating updater code...");
        let dos_header = module.handle() as *const IMAGE_DOS_HEADER;

        if (*dos_header).e_magic != 0x5A4D {
            return Err(SelfUpdateError::InvalidDosSignature);
        }

        let nt_header_address = module.handle().byte_offset((*dos_header).e_lfanew as isize);
        let nt_header = nt_header_address as *const IMAGE_NT_HEADERS32;

        if (*nt_header).Signature != 0x4550 {
            return Err(SelfUpdateError::InvalidNtSignature);
        }

        let number_of_sections = (*nt_header).FileHeader.NumberOfSections;

        if number_of_sections < 5 {
            return Err(SelfUpdateError::NoUpdaterCodeSection);
        }

        let section_header_offset = (&(*nt_header).OptionalHeader as *const _ as *const u8)
            .byte_add((*nt_header).FileHeader.SizeOfOptionalHeader as usize)
            as *const IMAGE_SECTION_HEADER;

        for i in 0..number_of_sections {
            let section_header = *section_header_offset.byte_add(40 * i as usize);
            let section_name = CStr::from_bytes_until_nul(&section_header.Name)
                .unwrap()
                .to_str()
                .unwrap();

            if section_name != ".rtext" {
                continue;
            }

            let src_addr = module
                .handle()
                .byte_add(section_header.VirtualAddress as usize)
                as *mut u8;
            let section_size = *section_header.Misc.VirtualSize() as usize;

            let dst_addr = VirtualAlloc(
                ptr::null_mut(),
                section_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ) as *mut u8;

            if dst_addr.is_null() {
                return Err(SelfUpdateError::FailedToAllocateMemory);
            }

            debug!(
                "Copying updater code section from {:p} to {:p}",
                src_addr, dst_addr
            );
            std::ptr::copy_nonoverlapping(src_addr, dst_addr, section_size);

            let updater_start_address = (replace_with_new_library as PROC)
                .byte_add(dst_addr as usize)
                .byte_sub(src_addr as usize);

            debug!("Making updater code executable");
            let mut old_protect = 0u32;
            let result = VirtualProtect(
                dst_addr as *mut _,
                section_size,
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );

            if result == 0 {
                return Err(SelfUpdateError::FailedVirtualProtect {
                    errno: GetLastError(),
                });
            }

            let process_heap = GetProcessHeap();
            let heap = HeapAlloc(
                process_heap,
                HEAP_ZERO_MEMORY,
                mem::size_of::<ReplaceArgs>(),
            ) as *mut ReplaceArgs;

            debug!("Allocated heap for updater code at {heap:p}");

            (*heap).module = module.handle();
            let old = U16CString::from_str_truncate(&module_filename);
            let new = U16CString::from_str_truncate(&new_module_path.to_string_lossy());
            std::ptr::copy_nonoverlapping(
                old.as_ptr(),
                (*heap).old.as_mut_ptr(),
                old.as_slice().len(),
            );
            std::ptr::copy_nonoverlapping(
                new.as_ptr(),
                (*heap).new.as_mut_ptr(),
                new.as_slice().len(),
            );

            debug!("Executing updater code at {updater_start_address:p}");
            let handle = CreateThread(
                ptr::null_mut(),
                0,
                Some(std::mem::transmute(updater_start_address)),
                heap as *mut _,
                0,
                ptr::null_mut(),
            );

            if handle.is_null() {
                error!("Could not execute updater code: {}", GetLastError());
                return Err(SelfUpdateError::FailedCreateThread {
                    errno: GetLastError(),
                });
            }

            return Ok(true);
        }

        return Err(SelfUpdateError::NoUpdaterCodeSection);
    }
}

fn validate_sha256(data: &[u8], expected: &str) -> Result<(), SelfUpdateError> {
    let mut hasher = Sha256::new();

    hasher.update(data);

    let hash = hasher.finalize();
    let hash_string = faster_hex::hex_string(&hash[..]);

    debug!("Expected checksum: {}", expected);
    debug!("Actual checksum: {}", hash_string);

    if hash_string != expected {
        return Err(SelfUpdateError::InvalidChecksum);
    }

    Ok(())
}

fn verify_signature(file: &str) -> Result<(), VerifySignatureError> {
    let file_osstr = U16CString::from_str_truncate(file);
    let mut verification_type = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let mut wintrust_data_buf = vec![0u8; mem::size_of::<WINTRUST_DATA>()];
    let mut fileinfo_buf = vec![0u8; mem::size_of::<WINTRUST_FILE_INFO>()];

    unsafe {
        let fileinfo = fileinfo_buf.as_mut_ptr() as *mut WINTRUST_FILE_INFO;
        let wintrust_data = wintrust_data_buf.as_mut_ptr() as *mut WINTRUST_DATA;

        (*fileinfo).cbStruct = mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        (*fileinfo).pcwszFilePath = file_osstr.as_ptr();
        (*fileinfo).hFile = ptr::null_mut();
        (*fileinfo).pgKnownSubject = ptr::null_mut();

        (*wintrust_data).pPolicyCallbackData = ptr::null_mut();
        (*wintrust_data).pSIPClientData = ptr::null_mut();
        (*wintrust_data).cbStruct = mem::size_of::<WINTRUST_DATA>() as u32;
        (*wintrust_data).dwStateAction = WTD_STATEACTION_VERIFY;
        (*wintrust_data).dwUIChoice = WTD_UI_NONE;
        (*wintrust_data).fdwRevocationChecks = WTD_REVOKE_NONE;
        (*wintrust_data).dwUnionChoice = WTD_CHOICE_FILE;
        (*wintrust_data).hWVTStateData = ptr::null_mut();
        (*wintrust_data).pwszURLReference = ptr::null_mut();
        (*wintrust_data).dwUIContext = 0;
        *(*wintrust_data).u.pFile_mut() = fileinfo;

        let status = WinVerifyTrust(
            ptr::null_mut(),
            &mut verification_type,
            wintrust_data as *mut _,
        );

        match status {
            0 | CERT_E_UNTRUSTEDROOT | CERT_E_EXPIRED | CERT_E_CHAINING => Ok(()),
            CRYPT_E_SECURITY_SETTINGS => Err(VerifySignatureError::VerificationDisabledByPolicy),
            TRUST_E_NOSIGNATURE => Err(VerifySignatureError::NoSignature),
            TRUST_E_EXPLICIT_DISTRUST => Err(VerifySignatureError::ExplicitlyDistrusted),
            _ => Err(VerifySignatureError::Unknown { errno: status }),
        }
    }
}

fn get_signature_pubkey(file: &str) -> Result<Vec<u8>, GetSignaturePubkeyError> {
    debug!("Getting public key of {file}.");

    let file_osstr = U16CString::from_str_truncate(file);
    let mut cert_store: HCERTSTORE = ptr::null_mut();
    let mut crypt_msg: HCRYPTMSG = ptr::null_mut();
    let result = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            file_osstr.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut cert_store,
            &mut crypt_msg,
            ptr::null_mut(),
        )
    };

    if result == 0 {
        return Err(GetSignaturePubkeyError::QueryObjectError {
            errno: unsafe { GetLastError() },
        });
    }

    let mut signer_info_length = 0;
    let result = unsafe {
        CryptMsgGetParam(
            crypt_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            ptr::null_mut(),
            &mut signer_info_length,
        )
    };

    if result == 0 {
        return Err(GetSignaturePubkeyError::SignerInfoSizeError {
            errno: unsafe { GetLastError() },
        });
    }

    let signer_info =
        unsafe { LocalAlloc(LMEM_ZEROINIT, signer_info_length as usize) } as PCMSG_SIGNER_INFO;

    if signer_info.is_null() {
        return Err(GetSignaturePubkeyError::SignerInfoAllocError {
            errno: unsafe { GetLastError() },
        });
    }

    let result = unsafe {
        CryptMsgGetParam(
            crypt_msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            signer_info as *mut _,
            &mut signer_info_length,
        )
    };

    if result == 0 {
        return Err(GetSignaturePubkeyError::SignerInfoObtainError {
            errno: unsafe { GetLastError() },
        });
    }

    let mut cert_search_params_buf = vec![0u8; mem::size_of::<CERT_INFO>()];
    let cert_search_params = cert_search_params_buf.as_mut_ptr() as *mut CERT_INFO;

    unsafe {
        (*cert_search_params).Issuer = (*signer_info).Issuer;
        (*cert_search_params).SerialNumber = (*signer_info).SerialNumber;
    }

    let cert = unsafe {
        CertFindCertificateInStore(
            cert_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            cert_search_params as *const _,
            ptr::null(),
        )
    };

    if cert.is_null() {
        return Err(GetSignaturePubkeyError::CertificateInStoreError {
            errno: unsafe { GetLastError() },
        });
    }

    unsafe {
        let cert_info = (*cert).pCertInfo;
        let cbb = (*cert_info).SubjectPublicKeyInfo.PublicKey;
        let public_key_length = cbb.cbData;
        let public_key = cbb.pbData;
        let mut public_key =
            std::slice::from_raw_parts(public_key as *const _, public_key_length as _);
        let mut pubkey_vec = Vec::with_capacity(public_key_length as _);

        public_key
            .read_to_end(&mut pubkey_vec)
            .context(ReadPubkeySnafu)?;

        CertCloseStore(cert_store, 0);
        CryptMsgClose(crypt_msg);

        Ok(pubkey_vec)
    }
}
