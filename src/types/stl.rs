use std::{
    ffi::{c_char, CStr},
    fmt::Display,
};

const INLINE_BUFFER_SIZE: usize = 16;

#[repr(C)]
pub union StdStringOptimization {
    ptr: *mut c_char,
    data: [c_char; INLINE_BUFFER_SIZE],
}

#[repr(C)]
pub struct StdString {
    pub data: StdStringOptimization,
    pub length: usize,
    pub capacity: usize,
}

impl StdString {
    unsafe fn as_cstr(&self) -> &CStr {
        if self.capacity < INLINE_BUFFER_SIZE {
            let ptr = &raw const self.data.data;
            CStr::from_ptr(ptr as *const _)
        } else if self.data.ptr.is_null() {
            CStr::from_bytes_until_nul(&[0u8]).unwrap()
        } else {
            CStr::from_ptr(self.data.ptr)
        }
    }
}

impl Display for StdString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = unsafe { self.as_cstr() }.to_string_lossy();
        f.write_str(&s)
    }
}

#[repr(C)]
pub struct StdListNode<T> {
    pub next: *mut StdListNode<T>,
    pub previous: *mut StdListNode<T>,
    pub value: T,
}

#[repr(C)]
pub struct StdList<T> {
    pub head: *mut StdListNode<T>,
    pub size: usize,
}

#[repr(C)]
pub struct StdVector<T> {
    pub first: *mut T,
    pub last: *mut T,
    pub end: *mut T,
}
