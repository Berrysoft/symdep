use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        elf: { any(target_os = "linux", target_os = "freebsd", target_os = "illumos", target_os = "solaris") }
    }
}
