use crate::ErrorKind::{CannotRead, NotAnElf, NotDynamic, StrtableBad};
use clap::Parser;
use goblin::elf::dynamic::{DT_STRSZ, DT_STRTAB};
use goblin::elf32::header::machine_to_str;
use goblin::strtab::Strtab;
use indicatif::ProgressIterator;
use itertools::Itertools;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Program to analyze which executables are using which shared libraries
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long)]
    executables_dir: PathBuf,
}

#[derive(Debug)]
enum ErrorKind {
    CannotRead(std::io::Error),
    NotAnElf(goblin::error::Error),
    NotDynamic,
    StrtableBad(goblin::error::Error),
}

fn process_one(path: &Path) -> Result<(u16, Vec<String>), ErrorKind> {
    let file = std::fs::read(&path).map_err(CannotRead)?;
    let elf = goblin::elf::Elf::parse(&file).map_err(NotAnElf)?;
    let dynamic = elf.dynamic.ok_or(NotDynamic)?;

    let dyn_strtable = dynamic
        .dyns
        .iter()
        .find(|t| t.d_tag == DT_STRTAB)
        .map(|t| t.d_val)
        .unwrap();
    let dyn_strtable_size = dynamic
        .dyns
        .iter()
        .find(|t| t.d_tag == DT_STRSZ)
        .map(|t| t.d_val)
        .unwrap();
    let table = Strtab::parse(&file, dyn_strtable as usize, dyn_strtable_size as usize, 0)
        .map_err(StrtableBad)?;

    Ok((
        elf.header.e_machine,
        dynamic
            .get_libraries(&table)
            .into_iter()
            .map(|l| l.to_string())
            .collect(),
    ))
}

fn main() {
    let args = Args::parse();

    let mut aboba = BTreeMap::new();

    let tree = WalkDir::new(&args.executables_dir)
        .into_iter()
        .collect::<Vec<_>>();

    for f in tree
        .into_iter()
        .progress()
        .filter_map(|f| f.ok())
        .filter(|f| {
            let m = f.metadata().unwrap();
            m.is_file() && m.permissions().mode() & 0o100 != 0
        })
        .map(|f| f.path().to_path_buf())
    {
        let res = process_one(&f);
        if let Ok((machine, res)) = res {
            for lib in res {
                let mentry = aboba.entry(machine);
                let aboba = mentry.or_insert(BTreeMap::new());

                let entry = aboba.entry(lib);
                entry.or_insert(Vec::new()).push(f.clone());
            }
        };
    }

    for (machine, aboba) in aboba {
        let machine = machine_to_str(machine);

        let mut output = File::create(format!("m_{}.txt", machine)).unwrap();

        for (soname, mut exes) in aboba
            .into_iter()
            .sorted_by_key(|(_, exes)| exes.len() as isize)
            .rev()
        {
            writeln!(output, "{} ({} exes)", soname, exes.len()).unwrap();
            exes.sort();
            for exe in exes {
                writeln!(output, "        <= {}", exe.to_str().unwrap()).unwrap();
            }
        }
    }
}
