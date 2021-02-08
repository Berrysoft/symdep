use goblin::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::*;
use structopt::StructOpt;

trait BinAnalyzer {
    fn description(&self) -> String;
    fn deps(&self) -> Vec<String>;
    fn imports(&self) -> Vec<String>;
    fn imp_deps(&self) -> BTreeMap<String, Vec<String>>;
    fn exports(&self) -> Vec<String>;
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
        let mut symbols = ana.exports();
        symbols.sort_unstable();
        for sym in symbols {
            println!("{}", sym);
        }
    } else if opt.deps && opt.imports {
        let deps = ana.imp_deps();
        for (dep, mut symbols) in deps {
            if !dep.is_empty() {
                println!("{}:", dep);
            }
            symbols.sort_unstable();
            for sym in symbols {
                println!("\t{}", sym);
            }
        }
    } else if opt.deps {
        let mut deps = ana.deps();
        deps.sort_unstable();
        for dep in deps {
            println!("{}:", dep);
        }
    } else if opt.imports {
        let mut symbols = ana.imports();
        symbols.sort_unstable();
        for sym in symbols {
            println!("{}", sym);
        }
    }
    Ok(())
}
