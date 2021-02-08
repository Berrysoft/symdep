use goblin::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::*;
use structopt::StructOpt;

trait BinAnalyzer {
    fn description(&self) -> String;
    fn deps(&self) -> BTreeSet<String>;
    fn imports(&self) -> BTreeSet<String>;
    fn imp_deps(&self) -> BTreeMap<String, BTreeSet<String>>;
    fn exports(&self) -> BTreeSet<String>;
}

mod elf;
mod mach;
mod pe;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "symdep",
    about = "A simple tool to view the import & export symbols of executable."
)]
struct Options {
    #[structopt(parse(from_os_str))]
    /// Input binary file.
    input: PathBuf,
    #[structopt(short, long)]
    /// Show dependencies.
    deps: bool,
    #[structopt(short, long)]
    /// Show export symbols.
    exports: bool,
    #[structopt(short, long)]
    /// Show import symbols.
    imports: bool,
}

fn main() -> error::Result<()> {
    let opt = Options::from_args();
    let buffer = fs::read(opt.input.as_path())?;
    let ana: Box<dyn BinAnalyzer> = match Object::parse(&buffer)? {
        Object::Elf(elf) => Box::new(elf::ElfAnalyzer::from_bin(elf)),
        Object::PE(pe) => Box::new(pe::PEAnalyzer::from_bin(pe)),
        Object::Mach(mach) => Box::new(mach::MachAnalyzer::from_bin(mach)),
        _ => {
            panic!("File type not supported.")
        }
    };
    println!(
        "{}: {}",
        opt.input.into_os_string().into_string().unwrap(),
        ana.description()
    );
    if opt.exports {
        for sym in ana.exports() {
            println!("{}", sym);
        }
    } else if opt.deps && opt.imports {
        let deps = ana.imp_deps();
        for (dep, symbols) in deps {
            if !dep.is_empty() {
                println!("{}:", dep);
            }
            for sym in symbols {
                println!("\t{}", sym);
            }
        }
    } else if opt.deps {
        for dep in ana.deps() {
            println!("{}", dep);
        }
    } else if opt.imports {
        for sym in ana.imports() {
            println!("{}", sym);
        }
    }
    Ok(())
}
