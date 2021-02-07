use goblin::*;
use std::env;
use std::fs;
use std::path::Path;

fn main() -> error::Result<()> {
    for (i, arg) in env::args().enumerate() {
        if i == 1 {
            let path = Path::new(arg.as_str());
            let buffer = fs::read(path)?;
            match Object::parse(&buffer)? {
                Object::Elf(elf) => {}
                Object::PE(pe) => {}
                Object::Mach(mach) => {}
                _ => {
                    println!("File type not supported.")
                }
            }
        }
    }
    Ok(())
}
