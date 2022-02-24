use std::{path::PathBuf, error::Error, ffi::c_void};

use clap::{AppSettings, Arg, ValueHint};
use libxdc::{elf_executable_page_cache::ElfExecutablePageCache, PT_TRACE_END};


fn main() -> Result<(), Box<dyn Error>> {
    let matches = clap::app_from_crate!()
        .setting(AppSettings::TrailingVarArg)
        .arg(
            Arg::new("ip_start")
                .required(true)
                .help("Starting address of the filter")
                .validator(parse_int::parse::<u64>)
                .value_hint(ValueHint::Other)
        )
        .arg(
            Arg::new("ip_end")
                .required(true)
                .help("Ending address of the filter")
                .validator(parse_int::parse::<u64>)
                .value_hint(ValueHint::Other)
        )
        .arg(
            Arg::new("binary")
                .required(true)
                .help("the binary being traced")
                .value_hint(ValueHint::FilePath)
        )
        .arg(
            Arg::new("trace_data")
                .required(true)
                .help("The file containing the serialized trace data to decode")
                .value_hint(ValueHint::FilePath)
        )
        .arg(
            Arg::new("final_hash")
                .required(true)
                .help("The hash of the trace for checking, I think???")
                .validator(parse_int::parse::<usize>)
                .value_hint(ValueHint::Other)
        )
        .get_matches();

    let filter_start: u64 = parse_int::parse(matches.value_of("filter_start").unwrap())?;
    let filter_end: u64 = parse_int::parse(matches.value_of("filter_end").unwrap())?;
    let bin_path = matches.value_of("binary_path").unwrap();
    let trace_data_path = matches.value_of("trace_data").unwrap();
    let final_hash : u64 = parse_int::parse(matches.value_of("final_hash").unwrap())?;
    let filter = [(filter_start, filter_end), (0,0), (0,0), (0,0)];

    let mut page_cache = ElfExecutablePageCache::executable_page_data_for_elf(bin_path, None)?;


    // let f = |addr| *
    let mut xdc = libxdc::LibXDC::new(&filter, |addr| {
        let mut_ref = page_cache.get_page_data(addr);
        mut_ref.map(|x| (x as *mut [u8; 0x1000]) as *mut c_void)
    }, 0x10000);
    xdc.enable_tracing();
    xdc.set_bb_callback(|mode, x, y| {
        println!("Hit bb! disasm_mode={mode:?}, x=0x{x:x}, y=0x{y:x}");
    });
    xdc.set_ip_callback(|x| {
        println!("Hit IP! x=0x{x:x}");
    });
    xdc.set_edge_callback(|x, y| {
        println!("Hit edge! 0x{x:x}->0x{y:x}");
    });

    let mut trace_data = std::fs::read(trace_data_path)?;
    if !trace_data.ends_with(&[PT_TRACE_END]) {
        trace_data.push(PT_TRACE_END)
    }
    xdc.decode(&trace_data);
    xdc.disable_tracing();
    println!("Bitmap hash: {:?}", xdc.get_bitmap_hash());
    println!("Pagefault addr: {:?}", xdc.get_pagefault_addr());

    Ok(())
}