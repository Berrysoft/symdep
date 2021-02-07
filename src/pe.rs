use crate::*;

pub struct PEAnalyzer<'a> {
    bin: goblin::pe::PE<'a>,
}

impl<'a> PEAnalyzer<'a> {
    pub fn from_bin(bin: goblin::pe::PE<'a>) -> Self {
        Self { bin }
    }
}

impl<'a> BinAnalyzer for PEAnalyzer<'a> {
    fn ana_dep(&self) -> HashMap<String, Vec<String>> {
        let mut map = HashMap::<String, Vec<String>>::new();
        for imp in &self.bin.imports {
            map.entry(imp.dll.to_string())
                .or_default()
                .push(imp.name.as_ref().to_owned());
        }
        map
    }
}
