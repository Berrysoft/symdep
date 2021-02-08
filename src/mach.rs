use crate::*;
use goblin::mach as gmach;

pub struct MachAnalyzer<'a> {
    bin: gmach::Mach<'a>,
}

impl<'a> MachAnalyzer<'a> {
    pub fn from_bin(bin: gmach::Mach<'a>) -> Self {
        Self { bin }
    }

    fn ana_dep_impl(bin: &gmach::MachO) -> BTreeMap<String, Vec<String>> {
        let mut map = BTreeMap::<String, Vec<String>>::new();
        if let Ok(imports) = bin.imports() {
            for imp in imports {
                map.entry(imp.dylib.to_owned())
                    .or_default()
                    .push(imp.name.to_owned());
            }
        }
        map
    }
}

impl<'a> BinAnalyzer for MachAnalyzer<'a> {
    fn ana_dep(&self) -> BTreeMap<String, Vec<String>> {
        match &self.bin {
            gmach::Mach::Binary(bin) => Self::ana_dep_impl(bin),
            gmach::Mach::Fat(multi) => {
                let mut map = BTreeMap::new();
                for bin in multi.into_iter() {
                    if let Ok(bin) = bin {
                        let mut smap = Self::ana_dep_impl(&bin);
                        map.append(&mut smap);
                    }
                }
                map
            }
        }
    }
}
