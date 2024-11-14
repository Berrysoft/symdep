use crate::*;
use goblin::elf as gelf;

#[cfg(elf)]
use std::path::PathBuf;

pub struct ElfAnalyzer<'a> {
    bin: gelf::Elf<'a>,
}

impl<'a> ElfAnalyzer<'a> {
    pub fn from_bin(bin: gelf::Elf<'a>) -> Self {
        Self { bin }
    }

    fn exports_impl(bin: &gelf::Elf) -> BTreeSet<String> {
        bin.dynsyms
            .iter()
            .filter(|sym| sym.st_value != 0)
            .map(|sym| {
                bin.dynstrtab
                    .get_unsafe(sym.st_name)
                    .map(|s| s.to_owned())
                    .unwrap_or_default()
            })
            .collect()
    }
}

#[cfg(elf)]
mod ldfind {
    use libc::{dlclose, dlerror, dlopen, RTLD_LAZY};
    use std::ffi::{c_void, CStr, CString, OsStr};
    use std::os::raw::c_char;
    use std::path::PathBuf;
    use std::ptr::null_mut;

    #[cfg(target_os = "linux")]
    use libc::{dlinfo, RTLD_DI_LINKMAP};

    #[cfg(not(target_os = "linux"))]
    const RTLD_DI_LINKMAP: i32 = 2;

    #[cfg(not(target_os = "linux"))]
    extern "C" {
        fn dlinfo(handle: *mut c_void, request: i32, p: *mut c_void) -> i32;
    }

    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct link_map64 {
        l_addr: u64,
        l_name: *mut c_char,
        l_ld: *mut goblin::elf64::dynamic::Dyn,
        l_next: *mut link_map64,
        l_prev: *mut link_map64,
    }

    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct link_map32 {
        l_addr: u32,
        l_name: *mut c_char,
        l_ld: *mut goblin::elf32::dynamic::Dyn,
        l_next: *mut link_map32,
        l_prev: *mut link_map32,
    }

    fn panic_dlerror() -> ! {
        panic!(
            "{}",
            unsafe { CStr::from_ptr(dlerror()) }
                .to_string_lossy()
                .as_ref()
        )
    }

    #[repr(transparent)]
    pub struct DynLib(*mut c_void);

    impl DynLib {
        pub fn open(path: &str) -> Self {
            let path = CString::new(path).unwrap();
            let handle = unsafe { dlopen(path.as_ptr(), RTLD_LAZY) };
            if handle.is_null() {
                panic_dlerror();
            }
            Self(handle)
        }

        pub fn full_path(&self, is_64: bool) -> Option<PathBuf> {
            unsafe {
                if is_64 {
                    let mut plink: *mut link_map64 = null_mut();
                    if dlinfo(self.0, RTLD_DI_LINKMAP, &mut plink as *mut _ as _) < 0 {
                        panic_dlerror();
                    }
                    if let Some(link) = plink.as_mut() {
                        if !link.l_name.is_null() {
                            return Some(PathBuf::from(OsStr::from_encoded_bytes_unchecked(
                                CStr::from_ptr(link.l_name).to_bytes(),
                            )));
                        }
                    }
                } else {
                    let mut plink: *mut link_map32 = null_mut();
                    if dlinfo(self.0, RTLD_DI_LINKMAP, &mut plink as *mut _ as _) < 0 {
                        panic_dlerror();
                    }
                    if let Some(link) = plink.as_mut() {
                        if !link.l_name.is_null() {
                            return Some(PathBuf::from(OsStr::from_encoded_bytes_unchecked(
                                CStr::from_ptr(link.l_name).to_bytes(),
                            )));
                        }
                    }
                }
            }
            None
        }
    }

    impl Drop for DynLib {
        fn drop(&mut self) {
            unsafe {
                dlclose(self.0);
            }
        }
    }
}

#[cfg(elf)]
impl<'a> ElfAnalyzer<'a> {
    fn find_bin_impl(&self, name: &str, path: &str) -> Option<PathBuf> {
        if let Ok(dir) = fs::read_dir(path) {
            for entry in dir.flatten() {
                if entry.file_name() == name {
                    return Some(entry.path());
                }
            }
        }
        None
    }

    fn find_bin(&self, name: &str) -> Option<PathBuf> {
        let dyns = &self.bin.dynamic.as_ref().unwrap().dyns;
        let mut rpath = None;
        let mut run_path = None;
        for d in dyns {
            match d.d_tag {
                gelf::dynamic::DT_RPATH => rpath = self.bin.dynstrtab.get_unsafe(d.d_val as _),
                gelf::dynamic::DT_RUNPATH => run_path = self.bin.dynstrtab.get_unsafe(d.d_val as _),
                _ => {}
            }
        }
        if let Some(path) = rpath {
            if let Some(buf) = self.find_bin_impl(name, path) {
                return Some(buf);
            }
        }
        if let Some(path) = option_env!("LD_LIBRARY_PATH") {
            for path in path.split(':') {
                if let Some(buf) = self.find_bin_impl(name, path) {
                    return Some(buf);
                }
            }
        }
        if let Some(path) = run_path {
            if let Some(buf) = self.find_bin_impl(name, path) {
                return Some(buf);
            }
        }
        let lib = ldfind::DynLib::open(name);
        lib.full_path(self.bin.is_64)
    }
}

fn is_import(sym: &gelf::Sym) -> bool {
    let bind = sym.st_bind();
    bind == gelf::sym::STB_GLOBAL || bind == gelf::sym::STB_WEAK
}

impl BinAnalyzer for ElfAnalyzer<'_> {
    fn description(&self) -> String {
        format!("ELF{}", if self.bin.is_64 { "64" } else { "32" })
    }

    fn deps(&self) -> BTreeSet<String> {
        self.bin
            .libraries
            .iter()
            .map(|lib| (*lib).to_owned())
            .collect()
    }

    fn imports(&self) -> BTreeSet<String> {
        self.bin
            .dynsyms
            .iter()
            .filter(is_import)
            .map(|sym| {
                self.bin
                    .dynstrtab
                    .get_unsafe(sym.st_name)
                    .map(|s| s.to_owned())
                    .unwrap_or_default()
            })
            .collect()
    }

    fn imp_deps(&self) -> BTreeMap<String, BTreeSet<String>> {
        #[allow(unused_mut)]
        let mut dynsyms = self.imports();
        let mut map = BTreeMap::<String, BTreeSet<String>>::new();
        #[cfg(elf)]
        for lib in self.bin.libraries.iter() {
            if let Some(lib_path) = self.find_bin(lib) {
                let buffer = fs::read(lib_path.as_path()).unwrap();
                if let Ok(bin) = gelf::Elf::parse(&buffer) {
                    let exports = Self::exports_impl(&bin);
                    let mut used_exports = dynsyms.intersection(&exports).cloned().collect();
                    dynsyms = dynsyms.difference(&exports).cloned().collect();
                    map.entry((*lib).to_owned())
                        .or_default()
                        .append(&mut used_exports);
                }
            }
        }
        if !dynsyms.is_empty() {
            map.insert("<Unknown dependency>".to_owned(), dynsyms);
        }
        map
    }

    fn exports(&self) -> BTreeSet<String> {
        Self::exports_impl(&self.bin)
    }
}
