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
        "#",
    ])
});

#[cfg(windows)]
fn msvc_demangle(name: &str) -> Option<String> {
    use std::{
        ffi::{CStr, CString},
        ptr::null_mut,
    };

    extern "C" {
        fn __unDName(
            buffer: *mut libc::c_char,
            mangled: *const libc::c_char,
            buflen: libc::c_int,
            memget: unsafe extern "C" fn(libc::size_t) -> *mut libc::c_void,
            memfree: unsafe extern "C" fn(*mut libc::c_void),
            flags: libc::c_uint,
        ) -> *mut libc::c_char;
    }

    let cname = CString::new(name).ok()?;
    let dname = unsafe {
        __unDName(
            null_mut(),
            cname.as_ptr(),
            0,
            libc::malloc,
            libc::free,
            0x8802,
        )
    };
    if dname.is_null() {
        return None;
    }

    struct FreeWrap<T>(*mut T);

    impl<T> Drop for FreeWrap<T> {
        fn drop(&mut self) {
            unsafe {
                libc::free(self.0.cast());
            }
        }
    }

    let dname = FreeWrap(dname);
    let dname = unsafe { CStr::from_ptr(dname.0) }.to_str().ok()?;
    if dname == name {
        None
    } else {
        Some(dname.to_string())
    }
}

#[inline]
fn demangle<'a>(name: &'a str, de: bool) -> Cow<'a, str> {
    let options = DemangleOptions::complete();
    if de {
        #[cfg(windows)]
        if let Some(name) = msvc_demangle(name) {
            return name.into();
        }
        if let Some(name) = Name::from(name).demangle(options) {
            return name.into();
        }
        for p in KNOWN_PREFIX.iter() {
            if let Some(name) = name.strip_prefix(p) {
                return format!("[{}] {}", p, demangle(name, de)).into();
            } else {
                // Mach-O prefix `_`
                let p = format!("_{p}");
                if let Some(name) = name.strip_prefix(&p) {
                    return format!("[{}] {}", p, demangle(name, de)).into();
                }
            }
        }
        // PE DLL reexports
        let s = name.split(" -> ").collect::<Vec<&str>>();
        if s.len() == 2 {
            let name0 = demangle(s[0], de);
            let name1 = s[1].split("!").collect::<Vec<&str>>();
            let rdll = name1[0];
            let name1 = demangle(name1[1], de);
            return format!("{name0} ->[[{rdll}]] {name1}").into();
        }
    }
    name.into()
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
