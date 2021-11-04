// build.rs

use std::env;
use std::fs;
use std::fs::*;
use std::io;
use std::path::Path;
use std::process::Command;

//Look all over the hard drive for a file
fn visit_dirs(
    dir: &Path,
    cb: &dyn Fn(&DirEntry) -> io::Result<Option<String>>,
) -> io::Result<Option<String>> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                match visit_dirs(&path, cb) {
                    Ok(op) => match op {
                        Some(st) => {
                            return Ok(Some(st));
                        }
                        None => {}
                    },
                    Err(_e) => {} // Ignore and keep moving. Maybe we don't have privileges
                }
            } else {
                match cb(&entry)? {
                    Some(st) => {
                        return Ok(Some(st));
                    }
                    None => {}
                }
            }
        }
    }
    Ok(None)
}

fn main() {
    println!("Running build.rs...");
    let pdirstr = env::var("CARGO_MANIFEST_DIR").expect("no manifest dir?");
    let target = env::var("TARGET").expect("no target env var?");
    if let Err(e) = env::set_current_dir(&Path::new(&pdirstr)) {
        eprintln!("Error setting path: {}", e);
    }
    println!("Project dir: {}", pdirstr);
    if cfg!(windows) {
        println!("cargo:rustc-link-lib=static=sodium");
        println!("cargo:rustc-link-search=native={}", pdirstr);
        println!("Compiling for windows");
        if Path::new("sodium.lib").exists() {
            println!("custom libsodium already built.");
            return;
        }
        println!("looking for vcvarsall.bat");
        if !Path::new("build.bat").exists() {
            let vcvarspath = match visit_dirs(Path::new("C:\\"), &|p: &DirEntry| {
                let pth = p.path();
                let fname = pth.file_name().unwrap().to_str().unwrap();
                if fname == "vcvarsall.bat" || fname == "vcvars64.bat" {
                    Ok(Some(p.path().to_str().unwrap().to_string()))
                } else {
                    Ok(None)
                }
            }) {
                Ok(op) => match op {
                    Some(mystr) => {
                        println!("Found vcvars batch script at {}", mystr);
                        mystr
                    }
                    None => {
                        println!("Could not find vcvars batch script");
                        return;
                    }
                },
                Err(e) => {
                    println!("Error visiting :-( {}", e);
                    return;
                }
            };
            //Make a batch file that will load the VS variables then run msbuild statically
            fs::write(
                "build.bat",
                format!(
                    "call \"{}\"\r\n\
                     cd ..\\libsodium\r\n\
                     msbuild /p:Configuration=Release\r\n\
                     copy /y Build\\Release\\x64\\libsodium.lib ..\\relay\\sodium.lib\r\n",
                    vcvarspath
                )
                .as_bytes(),
            )
            .unwrap_or_else(|e| eprintln!("Error writing build.bat: {}", e));
        }
        Command::new("cmd.exe")
            .args(&["/c", "build.bat"])
            .status()
            .unwrap();
    } else {
        //hope they have automake & friends
        let libsodium_a_folder = format!("./libsodium_{}/", target);
        let lap = format!("{}libsodium.a", libsodium_a_folder);
        let libsodium_a_path = Path::new(&lap);
        eprintln!("Building libsodium for target {}", target);
        if !libsodium_a_path.exists() {
            let mut stat = Command::new("./buildlibsodium.sh");
            if !stat.args(&[target]).status().unwrap().success() {
                panic!("libsodium build failed");
            }
        }
        println!("cargo:rustc-link-search=native={}", libsodium_a_folder);
        println!("cargo:rustc-link-lib=static=sodium");
    }
}
