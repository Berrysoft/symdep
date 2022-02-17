use crate::*;
use goblin::pe as gpe;

pub struct PEAnalyzer<'a> {
    bin: gpe::PE<'a>,
}

impl<'a> PEAnalyzer<'a> {
    pub fn from_bin(bin: gpe::PE<'a>) -> Self {
        Self { bin }
    }
}

impl<'a> BinAnalyzer for PEAnalyzer<'a> {
    fn description(&self) -> String {
        format!("PE{}", if self.bin.is_64 { "32+" } else { "32" })
    }

    fn deps(&self) -> BTreeSet<String> {
        self.bin
            .imports
            .iter()
            .map(|imp| imp.dll.to_string())
            .collect()
    }

    fn imports(&self) -> BTreeSet<String> {
        self.bin
            .imports
            .iter()
            .map(|imp| imp.name.as_ref().to_owned())
            .collect()
    }

    fn imp_deps(&self) -> BTreeMap<String, BTreeSet<String>> {
        let mut map = BTreeMap::<String, BTreeSet<String>>::new();
        for imp in &self.bin.imports {
            map.entry(imp.dll.to_string())
                .or_default()
                .insert(imp.name.as_ref().to_owned());
        }
        map
    }

    fn exports(&self) -> BTreeSet<String> {
        self.bin
            .exports
            .iter()
            .map(|exp| {
                let name = if let Some(name) = exp.name {
                    Cow::Borrowed(name)
                } else {
                    Cow::Owned(format!("OFFSET {}", exp.offset.unwrap_or_default()))
                };
                if let Some(reexp) = &exp.reexport {
                    match reexp {
                        gpe::export::Reexport::DLLName { export, lib } => {
                            format!("{} -> {}!{}", &name, *lib, *export)
                        }
                        gpe::export::Reexport::DLLOrdinal { ordinal, lib } => {
                            format!("{} -> {}!#{}", &name, *lib, *ordinal)
                        }
                    }
                } else {
                    name.as_ref().to_owned()
                }
            })
            .collect()
    }
}
