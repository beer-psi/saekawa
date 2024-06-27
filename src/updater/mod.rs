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
            CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_UNTRUSTEDROOT, CRYPT_E_SECURITY_SETTINGS, TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE
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
            WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        },
    },
};

use self::external::{replace_with_new_library, ReplaceArgs};
use crate::{
    consts::{GIT_SHA, PUBLIC_KEY, USER_AGENT},
    helpers::winapi_ext::{get_module_file_name, LibraryHandle, ReadStringFnError},
};

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
#[allow(clippy::large_enum_variant)]
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

    #[snafu(display("The signature failed to verify."))]
    SignatureBadDigest,

    #[snafu(display("The signature was explicitly distrusted."))]
    ExplicitlyDistrusted,

    #[snafu(display("An unknown validation error occured: {errno}"))]
    Unknown { errno: i32 },
}

#[derive(Snafu, Debug)]
pub enum GetSignaturePubkeyError {
    #[snafu(display("CertQueryObject failed: {errno}"))]
    QueryObject { errno: u32 },

    #[snafu(display("Could not obtain size of signer information: {errno}"))]
    SignerInfoSize { errno: u32 },

    #[snafu(display("Could not allocate memory for signer information: {errno}"))]
    SignerInfoAlloc { errno: u32 },

    #[snafu(display("Could not obtain signer information: {errno}"))]
    SignerInfoObtain { errno: u32 },

    #[snafu(display("Could not look up certificate in certificate store: {errno}"))]
    CertificateInStore { errno: u32 },

    #[snafu(display("Could not read public key."))]
    ReadPubkey { source: io::Error },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UpdateInformation {
    pub version: String,
    pub commit: String,
    pub sha256: String,
}

/// Checks if the hook has a newer version. Returns true if update was successful
/// and the hook should uninject itself so a newer version can load in.
#[allow(clippy::result_large_err)]
pub fn self_update(module: &LibraryHandle) -> Result<bool, SelfUpdateError> {
    let agent = ureq::builder()
        .user_agent(USER_AGENT)
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

    if response.commit == GIT_SHA {
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
            let old = U16CString::from_str_truncate(module_filename);
            let new = U16CString::from_str_truncate(new_module_filename);
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
                Some(std::mem::transmute::<PROC, unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> u32>(updater_start_address)),
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

        Err(SelfUpdateError::NoUpdaterCodeSection)
    }
}

#[allow(clippy::result_large_err)]
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

    unsafe {
        let mut fileinfo = mem::zeroed::<WINTRUST_FILE_INFO>();
        let mut wintrust_data = mem::zeroed::<WINTRUST_DATA>();

        fileinfo.cbStruct = mem::size_of::<WINTRUST_FILE_INFO>() as u32;
        fileinfo.pcwszFilePath = file_osstr.as_ptr();
        fileinfo.hFile = ptr::null_mut();
        fileinfo.pgKnownSubject = ptr::null_mut();

        wintrust_data.pPolicyCallbackData = ptr::null_mut();
        wintrust_data.pSIPClientData = ptr::null_mut();
        wintrust_data.cbStruct = mem::size_of::<WINTRUST_DATA>() as u32;
        wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        wintrust_data.dwUIChoice = WTD_UI_NONE;
        wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
        wintrust_data.hWVTStateData = ptr::null_mut();
        wintrust_data.pwszURLReference = ptr::null_mut();
        wintrust_data.dwUIContext = 0;
        *wintrust_data.u.pFile_mut() = &mut fileinfo as *mut _;

        let status = WinVerifyTrust(
            ptr::null_mut(),
            &mut verification_type,
            &mut wintrust_data as *mut _ as _,
        );

        wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;

        WinVerifyTrust(
            ptr::null_mut(),
            &mut verification_type,
            &mut wintrust_data as *mut _ as _,
        );

        match status {
            0 | CERT_E_UNTRUSTEDROOT | CERT_E_EXPIRED | CERT_E_CHAINING => Ok(()),
            CRYPT_E_SECURITY_SETTINGS => Err(VerifySignatureError::VerificationDisabledByPolicy),
            TRUST_E_NOSIGNATURE => Err(VerifySignatureError::NoSignature),
            TRUST_E_EXPLICIT_DISTRUST => Err(VerifySignatureError::ExplicitlyDistrusted),
            TRUST_E_BAD_DIGEST => Err(VerifySignatureError::SignatureBadDigest),
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
        return Err(GetSignaturePubkeyError::QueryObject {
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
        return Err(GetSignaturePubkeyError::SignerInfoSize {
            errno: unsafe { GetLastError() },
        });
    }

    let signer_info =
        unsafe { LocalAlloc(LMEM_ZEROINIT, signer_info_length as usize) } as PCMSG_SIGNER_INFO;

    if signer_info.is_null() {
        return Err(GetSignaturePubkeyError::SignerInfoAlloc {
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
        return Err(GetSignaturePubkeyError::SignerInfoObtain {
            errno: unsafe { GetLastError() },
        });
    }

    let cert_search_params = unsafe {
        let mut csp = mem::zeroed::<CERT_INFO>();

        csp.Issuer = (*signer_info).Issuer;
        csp.SerialNumber = (*signer_info).SerialNumber;

        csp
    };

    let cert = unsafe {
        CertFindCertificateInStore(
            cert_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            &cert_search_params as *const _ as _,
            ptr::null(),
        )
    };

    if cert.is_null() {
        return Err(GetSignaturePubkeyError::CertificateInStore {
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
