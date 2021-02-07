use goblin::*;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

trait BinAnalyzer {
    fn ana_dep(&self) -> BTreeMap<String, Vec<String>>;
}

mod elf;
mod pe;

fn main() -> error::Result<()> {
    if let Some(arg) = env::args().into_iter().nth(1) {
        let path = Path::new(arg.as_str());
        let buffer = fs::read(path)?;
        let deps = match Object::parse(&buffer)? {
            Object::Elf(elf) => {
                let ana = elf::ElfAnalyzer::from_bin(elf);
                ana.ana_dep()
            }
            Object::PE(pe) => {
                let ana = pe::PEAnalyzer::from_bin(pe);
                ana.ana_dep()
            }
            Object::Mach(_) => {
                todo!()
            }
            _ => {
                return Err(error::Error::Malformed(
                    "File type not supported.".to_owned(),
                ))
            }
        };
        for (dep, mut symbols) in deps {
            if !dep.is_empty() {
                println!("{}:", dep);
            }
            symbols.sort_unstable();
            for sym in symbols {
                println!("    {}", sym);
            }
        }
    }
    Ok(())
}
