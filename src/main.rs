use goblin::*;
use std::borrow::Cow;
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
    #[structopt(short = "m", long)]
    /// Demangle symbols.
    demangle: bool,
}

fn demangle_impl(name: Cow<str>) -> String {
    if let Ok(name) = msvc_demangler::demangle(&name, msvc_demangler::DemangleFlags::llvm()) {
        name
    } else {
        let dename = rustc_demangle::demangle(&name).to_string();
        if dename != name.as_ref() {
            dename
        } else if let Ok(sym) = cpp_demangle::Symbol::new(name.as_bytes()) {
            sym.to_string()
        } else {
            name.into_owned()
        }
    }
}

#[inline]
fn demangle<'a, S: Into<Cow<'a, str>>>(name: S, demangle: bool) -> String {
    if demangle {
        demangle_impl(name.into())
    } else {
        name.into().into_owned()
    }
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
                println!("{}:", dep);
            }
            for sym in symbols {
                println!("\t{}", demangle(&sym, opt.demangle));
            }
        }
    } else if opt.deps {
        for dep in ana.deps() {
            println!("{}", dep);
        }
    } else if opt.imports {
        for sym in ana.imports() {
            println!("{}", demangle(&sym, opt.demangle));
        }
    }
    Ok(())
}
