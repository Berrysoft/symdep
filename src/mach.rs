use crate::*;
use goblin::mach as gmach;

struct MachOAnalyzer<'a> {
    bin: gmach::MachO<'a>,
}

impl<'a> MachOAnalyzer<'a> {
    pub fn from_bin(bin: gmach::MachO<'a>) -> Self {
        Self { bin }
    }
}

impl<'a> BinAnalyzer for MachOAnalyzer<'a> {
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
                    .filter_map(|bin| bin.ok().map(|bin| MachOAnalyzer::from_bin(bin)))
                    .collect(),
            },
        }
    }
}

impl<'a> BinAnalyzer for MachAnalyzer<'a> {
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
        self.bins.iter().map(|bin| bin.deps()).flatten().collect()
    }

    fn imports(&self) -> BTreeSet<String> {
        self.bins
            .iter()
            .map(|bin| bin.imports())
            .flatten()
            .collect()
    }

    fn imp_deps(&self) -> BTreeMap<String, BTreeSet<String>> {
        self.bins
            .iter()
            .map(|bin| bin.imp_deps())
            .flatten()
            .collect()
    }

    fn exports(&self) -> BTreeSet<String> {
        self.bins
            .iter()
            .map(|bin| bin.exports())
            .flatten()
            .collect()
    }
}
