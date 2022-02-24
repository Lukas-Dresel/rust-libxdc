use std::{error::Error, collections::HashMap};

use goblin::elf::ProgramHeader;
use goblin::Object;
use goblin::elf64::program_header::PT_LOAD;

pub struct ElfExecutablePageCache {
    page_data: HashMap<u64, [u8; 0x1000]>,
    mapped_base: u64,
}

fn page_data_from_slice(slice: &[u8]) -> [u8; 0x1000]
{
    let mut a = [0u8;0x1000];
    assert!(slice.len() == 0x1000);
    a.as_mut().clone_from_slice(slice);
    a
}

static PAGE_SIZE: usize = 0x1000;

impl ElfExecutablePageCache {
    pub fn executable_page_data_for_elf(path: &str, mapped_base: Option<u64>) -> Result<ElfExecutablePageCache, Box<dyn Error>> {
        let data = std::fs::read(path)?;
        let elf = match Object::parse(&data)? {
            Object::Elf(e) => {
                assert!(e.is_64);
                Ok(e)
            },
            x => {
                Err(format!("Unknown object type! {x:?}"))
            }
        }?;
        let new_mapped_base = mapped_base.or_else(|| {
            if elf.is_64 {
                Some(0x0000555555554000)
            }
            else {
                Some(0x56555000)
            }
        }).unwrap();
        let elf_mapped_base: u64 = elf.program_headers.iter().filter_map(|x| if x.p_type == PT_LOAD {
            Some(x.vm_range().start)
        } else {
            None
        }).next().expect("Elf file does not contain LOAD segments??").try_into().unwrap();

        let page_data = elf.program_headers
            .iter()
            .filter_map(
                |hdr: &ProgramHeader| {
                    if hdr.p_type != PT_LOAD || !hdr.is_executable() {
                        return None;
                    }
                    let frng = hdr.file_range();
                    let vmrng = hdr.vm_range();
                    assert!(frng.len() <= vmrng.len());
                    let mut cur_data: Vec<u8> = data[frng].iter().map(|x| *x).collect();
                    cur_data.resize(vmrng.len(), 0u8);
                    let pages_iter = cur_data
                        .chunks_exact(PAGE_SIZE)
                        .enumerate()
                        .map(|(i, d)| {
                            let addr: u64 = ((i * PAGE_SIZE) + vmrng.start).try_into().unwrap();
                            let d = page_data_from_slice(&d);
                            (addr, d)
                        });
                    Some(pages_iter.collect::<HashMap<_, _>>())
                }
            )
            .flatten()
            .map(|(addr, data)| {
                (addr - elf_mapped_base + new_mapped_base, data)
            })
            .collect::<HashMap<_, _>>();
        Ok(ElfExecutablePageCache {
            mapped_base: new_mapped_base,
            page_data,
        })
    }
    pub fn get_page_data(&mut self, addr: u64) -> Option<&mut [u8; 0x1000]> {
        self.page_data.get_mut(&addr)
    }
}