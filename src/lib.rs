pub mod decoder_result;
pub mod elf_executable_page_cache;

use std::{ptr::null_mut, ffi::c_void};

use decoder_result::DecoderResult;
use libxdc_sys::*;

pub const PT_TRACE_END: u8 = 0x55;

fn get_release_version() -> u16 {
    unsafe {libxdc_get_release_version()}
}

//     pub fn decode_with_callback<F>(&mut self, callback: F) -> Result<(), PTDecoderStatus>
//         where F: FnMut(u64)
//     {
//         let mut callback = callback;
//         unsafe {
//             let context = &mut callback as *mut F as *mut c_void;
//
//             let res = ha_session_decode(self.sess, Some(coverage_trampoline::<F>), context);
//             assert!(res < 0, "ha_session_decode should always return -EOF on success!");
//             let res: PTDecoderStatus = (-res).try_into().unwrap();
//             match res {
//                 PTDecoderStatus::EndOfStream => Ok(()),
//                 _ => Err(res)
//             }
//         }
//     }

extern "C" fn edge_cb_trampoline<F>(opaque: *mut c_void, src: u64, dst: u64)
    where F: FnMut(u64, u64)
{
    unsafe {
        let cb = &mut *(opaque as *mut F);
        (cb)(src, dst)
    }
}
extern "C" fn ip_cb_trampoline<F>(opaque: *mut c_void, ip: u64)
    where F: FnMut(u64)
{
    unsafe {
        let cb = &mut *(opaque as *mut F);
        (cb)(ip)
    }
}
extern "C" fn bb_cb_trampoline<F>(opaque: *mut c_void, mode: disassembler_mode_t, start_addr: u64, cofi_addr: u64)
    where F: FnMut(disassembler_mode_t, u64, u64)
{
    unsafe {
        let cb = &mut *(opaque as *mut F);
        (cb)(mode, start_addr, cofi_addr)
    }
}
extern "C" fn page_cache_fetch_trampoline<CacheF>(opaque: *mut c_void, addr: u64, result: *mut bool) -> *mut c_void
    where CacheF: FnMut(u64) -> Option<*mut c_void>
{
    unsafe {
        let cb = &mut *(opaque as *mut CacheF);
        if let Some(res) = (cb)(addr) {
            *result = true;
            res
        }
        else {
            *result = false;
            std::ptr::null_mut()
        }
    }
}

pub struct LibXDC<CacheF>
    where CacheF: FnMut(u64) -> Option<*mut c_void>
{
    wrapped: *mut libxdc_t,
    page_cache_fetch: CacheF,
    bitmap: Vec<u8>,
}

impl<CacheF> Drop for LibXDC<CacheF>
    where CacheF: FnMut(u64) -> Option<*mut c_void>
{
    fn drop(&mut self) {
        unsafe {
            libxdc_free(self.wrapped);
        }
        self.wrapped = null_mut();
    }
}
impl<CacheF> LibXDC<CacheF>
    where CacheF: FnMut(u64) -> Option<*mut c_void>
{
    pub fn new(filter: &[(u64,u64); 4], page_cache_fetch: CacheF, bitmap_size: usize) -> LibXDC<CacheF> {
        let filters = filter.iter().map(|(x, y)| [*x, *y]).collect::<Vec<_>>();
        let mut bitmap = Vec::with_capacity(bitmap_size);
        bitmap.resize(bitmap_size, 0u8);
        let mut out = LibXDC {
            wrapped: std::ptr::null_mut(),
            page_cache_fetch: page_cache_fetch,
            bitmap,
        };
        unsafe {
            let context = (&mut out.page_cache_fetch) as *mut CacheF as *mut c_void;
            let res = libxdc_init(
                filters.as_ptr(),
                Some(page_cache_fetch_trampoline::<CacheF>),
                context,
                out.bitmap.as_mut_ptr() as *mut c_void,
                bitmap_size.try_into().expect("The bitmap size cannot be >= 2**64")
            );
            assert!(!res.is_null(), "LibXDC Initializiation failed!");
            out.wrapped = res
        }
        out
    }
    pub fn reset_trace_cache(&mut self) {
        unsafe { libxdc_reset_trace_cache(self.wrapped) }
    }
    pub fn reset_bitmap(&mut self) {
        unsafe { libxdc_bitmap_reset(self.wrapped) }
    }
    pub fn enable_tracing(&mut self) {
        unsafe {
            libxdc_enable_tracing(self.wrapped)
        }
    }
    pub fn disable_tracing(&mut self) {
        unsafe {
            libxdc_disable_tracing(self.wrapped)
        }
    }
    pub fn set_bb_callback<F>(&mut self, mut callback: F)
        where F: FnMut(disassembler_mode_t, u64, u64)
    {
        unsafe {
            let context = &mut callback as *mut F as *mut c_void;
            libxdc_register_bb_callback(self.wrapped, Some(bb_cb_trampoline::<F>), context)
        }
    }
    pub fn set_edge_callback<F>(&mut self, mut callback: F)
        where F: FnMut(u64, u64)
    {
        unsafe {
            let context = &mut callback as *mut F as *mut c_void;
            libxdc_register_edge_callback(self.wrapped, Some(edge_cb_trampoline::<F>), context)
        }
    }
    pub fn set_ip_callback<F>(&mut self, mut callback: F)
        where F: FnMut(u64)
    {
        unsafe {
            let context = &mut callback as *mut F as *mut c_void;
            libxdc_register_ip_callback(self.wrapped, Some(ip_cb_trampoline::<F>), context)
        }
    }
    pub fn decode(&mut self, data: &[u8]) -> DecoderResult {
        assert!(data.len() > 0);
        assert!(data[data.len() - 1] == 0x55);

        unsafe {
            let res = libxdc_decode(self.wrapped, data.as_ptr(), (data.len() - 1).try_into().unwrap());
            res.try_into().expect(&format!("Could not parse DecoderResult from libxdc_decode call: {}", res))
        }
    }
    pub fn get_bitmap_hash(&self) -> u64 {
        unsafe {
            libxdc_bitmap_get_hash(self.wrapped)
        }
    }
    pub fn get_pagefault_addr(&self) -> u64 {
        unsafe {
            libxdc_get_page_fault_addr(self.wrapped)
        }
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
