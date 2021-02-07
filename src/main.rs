use goblin::*;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

trait BinAnalyzer {
    fn ana_dep(&self) -> HashMap<String, Vec<String>>;
}

mod pe;

fn main() -> error::Result<()> {
    if let Some(arg) = env::args().into_iter().nth(1) {
        let path = Path::new(arg.as_str());
        let buffer = fs::read(path)?;
        let deps = match Object::parse(&buffer)? {
            Object::Elf(_) => {
                todo!()
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
        for (dep, symbols) in deps {
            println!("{}:", dep);
            for sym in symbols {
                println!("    {}", sym);
            }
        }
    }
    Ok(())
}
