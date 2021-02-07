use crate::*;
use std::path::PathBuf;

pub struct ElfAnalyzer<'a> {
    bin: goblin::elf::Elf<'a>,
}

impl<'a> ElfAnalyzer<'a> {
    pub fn from_bin(bin: goblin::elf::Elf<'a>) -> Self {
        Self { bin }
    }

    fn find_bin_impl(&self, name: &str, path: &str) -> Option<PathBuf> {
        if let Ok(dir) = fs::read_dir(path) {
            for entry in dir {
                if let Ok(entry) = entry {
                    if entry.file_name() == name {
                        return Some(entry.path());
                    }
                }
            }
        }
        None
    }

    fn find_bin(&self, name: &str) -> Option<PathBuf> {
        if name.contains('/') {
            return Some(PathBuf::from(name));
        }
        let dyns = &self.bin.dynamic.as_ref().unwrap().dyns;
        let mut rpath = None;
        let mut run_path = None;
        for d in dyns {
            match d.d_tag {
                goblin::elf::dynamic::DT_RPATH => {
                    rpath = Some(self.bin.strtab.get_unsafe(d.d_val as _).unwrap().to_owned())
                }
                goblin::elf::dynamic::DT_RUNPATH => {
                    run_path = Some(self.bin.strtab.get_unsafe(d.d_val as _).unwrap().to_owned())
                }
                _ => {}
            }
        }
        if let Some(ref path) = rpath {
            if let Some(buf) = self.find_bin_impl(name, path) {
                return Some(buf);
            }
        }
        if let Some(path) = option_env!("LD_LIBRARY_PATH") {
            if let Some(buf) = self.find_bin_impl(name, path) {
                return Some(buf);
            }
        }
        if let Some(ref path) = run_path {
            if let Some(buf) = self.find_bin_impl(name, path) {
                return Some(buf);
            }
        }
        if let Some(buf) = self.find_bin_impl(name, "/lib") {
            return Some(buf);
        }
        if let Some(buf) = self.find_bin_impl(name, "/usr/lib") {
            return Some(buf);
        }
        None
    }
}

impl<'a> BinAnalyzer for ElfAnalyzer<'a> {
    fn ana_dep(&self) -> HashMap<String, Vec<String>> {
        let mut dynsyms = self
            .bin
            .dynsyms
            .iter()
            .filter(|sym| sym.is_import())
            .map(|sym| self.bin.dynstrtab.get_unsafe(sym.st_name).unwrap())
            .collect::<Vec<_>>();
        dynsyms.sort_unstable();
        let mut map = HashMap::<String, Vec<String>>::new();
        for lib in self.bin.libraries.iter() {
            if let Some(lib_path) = self.find_bin(*lib) {
                let buffer = fs::read(lib_path.as_path()).unwrap();
                if let Ok(bin) = goblin::elf::Elf::parse(&buffer) {
                    for sym in bin.dynsyms.iter() {
                        let sym_name = bin.dynstrtab.get_unsafe(sym.st_name).unwrap();
                        let index = dynsyms.iter().position(|s| *s == sym_name);
                        let bind = sym.st_bind();
                        let is_export = bind != goblin::elf::sym::STB_WEAK && sym.st_value != 0;
                        if is_export && index.is_some() {
                            dynsyms.remove(index.unwrap());
                            map.entry((*lib).to_owned())
                                .or_default()
                                .push(sym_name.to_owned());
                        }
                    }
                }
            }
        }
        map
    }
}
