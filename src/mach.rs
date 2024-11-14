use crate::*;
use goblin::mach::{self as gmach, SingleArch};

struct MachOAnalyzer<'a> {
    bin: gmach::MachO<'a>,
}

impl<'a> MachOAnalyzer<'a> {
    pub fn from_bin(bin: gmach::MachO<'a>) -> Self {
        Self { bin }
    }
}

impl BinAnalyzer for MachOAnalyzer<'_> {
    fn description(&self) -> String {
        format!("Mach-O {}", self.bin.header.cputype())
    }

    fn deps(&self) -> BTreeSet<String> {
        self.bin.libs.iter().map(|s| (*s).to_owned()).collect()
    }

    fn imports(&self) -> BTreeSet<String> {
        self.bin
            .imports()
            .map(|imps| imps.iter().map(|imp| imp.name.to_owned()).collect())
            .unwrap_or_default()
    }

    fn imp_deps(&self) -> BTreeMap<String, BTreeSet<String>> {
        let mut map = BTreeMap::<String, BTreeSet<String>>::new();
        if let Ok(imports) = self.bin.imports() {
            for imp in imports {
                map.entry(imp.dylib.to_owned())
                    .or_default()
                    .insert(imp.name.to_owned());
            }
        }
        map
    }

    fn exports(&self) -> BTreeSet<String> {
        self.bin
            .exports()
            .map(|exps| exps.iter().map(|exp| exp.name.to_owned()).collect())
            .unwrap_or_default()
    }
}

pub struct MachAnalyzer<'a> {
    bins: Vec<MachOAnalyzer<'a>>,
}

impl<'a> MachAnalyzer<'a> {
    pub fn from_bin(bin: gmach::Mach<'a>) -> Self {
        Self {
            bins: match bin {
                gmach::Mach::Binary(bin) => vec![MachOAnalyzer::from_bin(bin)],
                gmach::Mach::Fat(multi) => multi
                    .into_iter()
                    .filter_map(|bin| {
                        bin.ok().and_then(|bin| match bin {
                            SingleArch::MachO(bin) => Some(MachOAnalyzer::from_bin(bin)),
                            _ => None,
                        })
                    })
                    .collect(),
            },
        }
    }
}

impl BinAnalyzer for MachAnalyzer<'_> {
    fn description(&self) -> String {
        let des = self
            .bins
            .iter()
            .map(|bin| bin.description())
            .collect::<Vec<_>>()
            .join("; ");
        if self.bins.len() <= 1 {
            des
        } else {
            format!("Fat: {}", des)
        }
    }

    fn deps(&self) -> BTreeSet<String> {
        self.bins.iter().flat_map(|bin| bin.deps()).collect()
    }

    fn imports(&self) -> BTreeSet<String> {
        self.bins.iter().flat_map(|bin| bin.imports()).collect()
    }

    fn imp_deps(&self) -> BTreeMap<String, BTreeSet<String>> {
        self.bins.iter().flat_map(|bin| bin.imp_deps()).collect()
    }

    fn exports(&self) -> BTreeSet<String> {
        self.bins.iter().flat_map(|bin| bin.exports()).collect()
    }
}
