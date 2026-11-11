//! Embeds every weakness card file under `data/weaknesses/cards/` into the binary.
use std::{env, fs, path::Path};

fn collect(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|e| e.expect("directory entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

fn main() {
    let root = Path::new(&env::var("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .join("data/weaknesses/cards");
    println!("cargo:rerun-if-changed={}", root.display());
    let mut files = vec![];
    collect(&root, &mut files);
    let mut code = String::from("pub const CARD_FILES: &[(&str, &[u8])] = &[\n");
    for path in files {
        let name = path
            .strip_prefix(&root)
            .expect("under the cards directory")
            .to_str()
            .expect("UTF-8 path")
            .replace('\\', "/");
        code.push_str(&format!(
            "    ({name:?}, include_bytes!({:?})),\n",
            path.to_str().expect("UTF-8 path")
        ));
    }
    code.push_str("];\n");
    let out = Path::new(&env::var("OUT_DIR").expect("out dir")).join("card_files.rs");
    fs::write(out, code).expect("writing card_files.rs");
}
