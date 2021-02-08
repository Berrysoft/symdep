# SymDep
A simple tool to view the import & export symbols of executable.

## Usage
``` sh
# Show dependencies
$ symdep <file> -d
# Show import symbols
$ symdep <file> -i
# Show import symbols group by dependencies
$ symdep <file> -id
# Show export symbols
$ symdep <file> -e
```

## Support binary types
It uses `goblin` package to read the binaries.
* ELF(32, 64)
* PE(32, 32+)
* MachO/Fat MachO

## Note for ELF
ELF doesn't require a symbol should be found in a specific library for convience.
Therefore, `symdep` tries to do the same as `ld.so` to find the libraries for the symbols.
