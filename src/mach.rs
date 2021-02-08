use crate::*;
use goblin::mach as gmach;

pub struct MachAnalyzer<'a> {
    bin: gmach::Mach<'a>,
}

impl<'a> MachAnalyzer<'a> {
    pub fn from_bin(bin: gmach::Mach<'a>) -> Self {
        Self { bin }
    }

    fn deps_impl(bin: &gmach::MachO) -> BTreeSet<String> {
        bin.libs.iter().map(|s| (*s).to_owned()).collect()
    }

    fn imports_impl(bin: &gmach::MachO) -> BTreeSet<String> {
        bin.imports()
            .map(|imps| imps.iter().map(|imp| imp.name.to_owned()).collect())
            .unwrap_or_default()
    }

    fn imp_deps_impl(bin: &gmach::MachO) -> BTreeMap<String, BTreeSet<String>> {
        let mut map = BTreeMap::<String, BTreeSet<String>>::new();
        if let Ok(imports) = bin.imports() {
            for imp in imports {
                map.entry(imp.dylib.to_owned())
                    .or_default()
                    .insert(imp.name.to_owned());
            }
        }
        map
    }

    fn exports_impl(bin: &gmach::MachO) -> BTreeSet<String> {
        bin.exports()
            .map(|exps| exps.iter().map(|exp| exp.name.to_owned()).collect())
            .unwrap_or_default()
    }
}

impl<'a> BinAnalyzer for MachAnalyzer<'a> {
    fn description(&self) -> String {
        match &self.bin {
            gmach::Mach::Binary(bin) => format!("MachO, {}", bin.header.cputype()),
            gmach::Mach::Fat(multi) => format!(
                "Fat MachO, {}",
                multi
                    .into_iter()
                    .map(|bin| bin.unwrap().header.cputype().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }

    fn deps(&self) -> BTreeSet<String> {
        match &self.bin {
            gmach::Mach::Binary(bin) => Self::deps_impl(bin),
            gmach::Mach::Fat(multi) => {
                let mut set = BTreeSet::new();
                for bin in multi.into_iter() {
                    if let Ok(bin) = bin {
                        set.append(&mut Self::deps_impl(&bin));
                    }
                }
                set
            }
        }
    }

    fn imports(&self) -> BTreeSet<String> {
        match &self.bin {
            gmach::Mach::Binary(bin) => Self::imports_impl(bin),
            gmach::Mach::Fat(multi) => {
                let mut set = BTreeSet::new();
                for bin in multi.into_iter() {
                    if let Ok(bin) = bin {
                        set.append(&mut Self::imports_impl(&bin));
                    }
                }
                set
            }
        }
    }

    fn imp_deps(&self) -> BTreeMap<String, BTreeSet<String>> {
        match &self.bin {
            gmach::Mach::Binary(bin) => Self::imp_deps_impl(bin),
            gmach::Mach::Fat(multi) => {
                let mut map = BTreeMap::new();
                for bin in multi.into_iter() {
                    if let Ok(bin) = bin {
                        map.append(&mut Self::imp_deps_impl(&bin));
                    }
                }
                map
            }
        }
    }

    fn exports(&self) -> BTreeSet<String> {
        match &self.bin {
            gmach::Mach::Binary(bin) => Self::exports_impl(bin),
            gmach::Mach::Fat(multi) => {
                let mut set = BTreeSet::new();
                for bin in multi.into_iter() {
                    if let Ok(bin) = bin {
                        set.append(&mut Self::exports_impl(&bin));
                    }
                }
                set
            }
        }
    }
}
