use std::path::PathBuf;
use std::str::FromStr;
use std::{env, fs};

fn main() {
    println!("cargo:rerun-if-changed=src/include/wrapper.h");
    println!("cargo:rerun-if-changed=src/wrapper.cc");
    println!("cargo:rerun-if-changed=src/ffi.rs");

    let mut wrapper_include_dir = env::current_dir().unwrap();
    wrapper_include_dir.push("src/include");

    let mut modsec_dir = env::current_dir().unwrap();
    modsec_dir.push("dep/ModSecurity");

    let mut dep_build_dir = env::current_dir().unwrap();
    dep_build_dir.push("dep/build");

    let mut modsec_include_dir = dep_build_dir.clone();
    modsec_include_dir.push("include");

    let mut lib_dir = dep_build_dir.clone();
    lib_dir.push("lib");

    if !modsec_include_dir.exists() {
        std::process::Command::new("git")
            .arg("submodule")
            .arg("update")
            .arg("--init")
            .arg("--recursive")
            .output()
            .unwrap();

        std::process::Command::new("./build.sh")
            .current_dir(&modsec_dir)
            .output()
            .unwrap();

        std::process::Command::new("./configure")
            .current_dir(&modsec_dir)
            .arg("--with-maxmind=no")
            .arg("--without-lua")
            .arg("--without-curl")
            .arg(format!("--prefix={}", dep_build_dir.display()))
            .arg("--with-libxml=no")
            .output()
            .unwrap();

        std::process::Command::new("make")
            .current_dir(&modsec_dir)
            .output()
            .unwrap();

        std::process::Command::new("make")
            .arg("install")
            .current_dir(&modsec_dir)
            .output()
            .unwrap();
    }

    cxx_build::bridge("src/ffi.rs") // returns a cc::Build
        .include(wrapper_include_dir)
        .include(modsec_include_dir)
        .file("src/wrapper.cc")
        .flag_if_supported("-std=c++14")
        .compile("rust-modsecurity");

    let lib = pkg_config::probe_library("libpcre").unwrap();
    for link_paths in lib.link_paths {
        println!("cargo:rustc-flags=-L {}", link_paths.display());
    }
    for lib in lib.libs {
        println!("cargo:rustc-link-lib=static={}", lib);
    }

    let out_dir = PathBuf::from_str(env::var("OUT_DIR").unwrap().as_str()).unwrap();
    let mut from = lib_dir.clone();
    from.push("libmodsecurity.a");

    let mut to = out_dir.clone();
    to.push("libmodsecurity.a");

    fs::copy(from, to).unwrap();

    let target = env::var("TARGET").unwrap();

    println!("cargo:rustc-flags=-L {}", out_dir.display());
    println!("cargo:rustc-link-lib=static=modsecurity");
    if target.contains("apple") || target.contains("freebsd") || target.contains("openbsd") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else if target.contains("linux") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }
}
