use clap::Parser;
use goblin::*;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::*;
use std::sync::LazyLock;
use symbolic_common::Name;
use symbolic_demangle::{Demangle, DemangleOptions};

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

#[derive(Debug, Parser)]
#[clap(
    author,
    version,
    about = "A simple tool to view the import & export symbols of executable."
)]
struct Options {
    /// Input binary file.
    input: PathBuf,
    #[clap(short, long)]
    /// Show dependencies.
    deps: bool,
    #[clap(short, long)]
    /// Show export symbols.
    exports: bool,
    #[clap(short, long)]
    /// Show import symbols.
    imports: bool,
    #[clap(short = 'm', long)]
    /// Demangle symbols.
    demangle: bool,
}

static KNOWN_PREFIX: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "__imp_",
        "__wrap_",
        "__emutls_v.",
        "__emutls_t.",
        "_GLOBAL__sub_I_",
        "__gcov_",
        "__gcda_",
        "__llvm_gcov_",
    ])
});

#[inline]
fn demangle<'a>(name: impl Into<Cow<'a, str>>, de: bool) -> Cow<'a, str> {
    let name = name.into();
    let options = DemangleOptions::complete();
    if de {
        if let Some(name) = Name::from(&*name).demangle(options) {
            return name.into();
        }
        for p in KNOWN_PREFIX.iter() {
            if let Some(name) = name.strip_prefix(p) {
                return format!("[{}] {}", p, demangle(name, de)).into();
            } else {
                let p = format!("_{p}");
                if let Some(name) = name.strip_prefix(&p) {
                    return format!("[{}] {}", p, demangle(name, de)).into();
                }
            }
        }
    }
    name
}

fn main() -> error::Result<()> {
    let opt = Options::parse();
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
        opt.input.file_name().unwrap().to_string_lossy().as_ref(),
        ana.description()
    );
    if opt.exports {
        for sym in ana.exports() {
            println!("{}", demangle(&sym, opt.demangle));
        }
    } else if opt.deps && opt.imports {
        let deps = ana.imp_deps();
        for (dep, symbols) in deps {
            if !dep.is_empty() {
                println!("{dep}:");
            }
            for sym in symbols {
                println!("\t{}", demangle(&sym, opt.demangle));
            }
        }
    } else if opt.deps {
        for dep in ana.deps() {
            println!("{dep}");
        }
    } else if opt.imports {
        for sym in ana.imports() {
            println!("{}", demangle(&sym, opt.demangle));
        }
    }
    Ok(())
}
