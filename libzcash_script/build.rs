//! Build script for zcash_script.

use std::{env, fmt, path::PathBuf};

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
enum Error {
    GenerateBindings,
    WriteBindings(std::io::Error),
    Env(std::env::VarError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::GenerateBindings => write!(f, "unable to generate bindings: try running 'git submodule init' and 'git submodule update'"),
            Error::WriteBindings(source) => write!(f, "unable to write bindings: {source}"),
            Error::Env(source) => source.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

// `bindgen::RustTarget::Stable_*` is deprecated in bindgen >= 0.71.0, but we are constrained
// downstream by the version supported by librocksdb-sys. However, one of our CI jobs still manages
// to pull a newer version, so this silences the deprecation on that job.
#[allow(deprecated)]
fn bindgen_headers() -> Result<()> {
    println!("cargo:rerun-if-changed=depend/zcash/src/script/zcash_script.h");

    let bindings = bindgen::Builder::default()
        .header("depend/zcash/src/script/zcash_script.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // This can be removed once rust-lang/rust-bindgen#3049 is fixed.
        .rust_target(
            env!("CARGO_PKG_RUST_VERSION")
                .parse()
                .expect("Cargo ‘rust-version’ is a valid value"),
        )
        .use_core()
        // Finish the builder and generate the bindings.
        .generate()
        .map_err(|_| Error::GenerateBindings)?;

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = env::var("OUT_DIR").map_err(Error::Env)?;
    let out_path = PathBuf::from(out_path);
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .map_err(Error::WriteBindings)?;

    Ok(())
}

fn main() -> Result<()> {
    bindgen_headers()?;

    let target = env::var("TARGET").expect("TARGET was not set");
    let mut base_config = cc::Build::new();

    language_std(&mut base_config, "c++17");

    base_config
        .include("depend/zcash/src/")
        .include("depend/zcash/src/rust/include/")
        .include("depend/zcash/src/secp256k1/include/")
        .include("depend/expected/include/")
        .flag_if_supported("-Wno-implicit-fallthrough")
        .flag_if_supported("-Wno-catch-value")
        .flag_if_supported("-Wno-reorder")
        .flag_if_supported("-Wno-deprecated-copy")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-variable")
        .flag_if_supported("-Wno-ignored-qualifiers")
        .flag_if_supported("-Wno-sign-compare")
        // when compiling using Microsoft Visual C++, ignore warnings about unused arguments
        .flag_if_supported("/wd4100")
        .define("HAVE_DECL_STRNLEN", "1")
        .define("__STDC_FORMAT_MACROS", None)
        // libsecp256k1 is linked statically. Without this, its headers declare the API as
        // imported from a DLL on Windows.
        .define("SECP256K1_STATIC", None);

    if target.contains("windows") {
        base_config.define("WIN32", "1");
    }

    base_config
        .file("depend/zcash/src/amount.cpp")
        .file("depend/zcash/src/crypto/ripemd160.cpp")
        .file("depend/zcash/src/crypto/sha1.cpp")
        .file("depend/zcash/src/crypto/sha256.cpp")
        .file("depend/zcash/src/pubkey.cpp")
        .file("depend/zcash/src/script/interpreter.cpp")
        .file("depend/zcash/src/script/script_error.cpp")
        .file("depend/zcash/src/script/script.cpp")
        .file("depend/zcash/src/script/zcash_script.cpp")
        .file("depend/zcash/src/uint256.cpp")
        .file("depend/zcash/src/util/strencodings.cpp")
        .compile("libzcash_script.a");

    // **Secp256k1**
    // Static libraries resolve symbols only from libraries linked after them, so
    // `libzcash_script` must precede the `secp256k1` library it calls into.
    if !cfg!(feature = "external-secp") {
        build_secp256k1();
    }

    Ok(())
}

/// Build the `secp256k1` library.
///
/// This is the libsecp256k1 release that `secp256k1-sys` vendors, built with the same modules
/// and precomputation parameters but with unprefixed symbols. A build that sets
/// `--cfg rust_secp_no_symbol_renaming` therefore links the Rust `secp256k1` bindings against
/// this library, so that the final artifact contains a single copy of libsecp256k1.
fn build_secp256k1() {
    let mut build = cc::Build::new();

    // Compile C99 code
    language_std(&mut build, "c99");

    build
        .include("depend/zcash/src/secp256k1/")
        .include("depend/zcash/src/secp256k1/include/")
        .include("depend/zcash/src/secp256k1/src/")
        // Some ecmult stuff is defined but not used upstream
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-parameter")
        // The modules that `secp256k1-sys` enables, so that its bindings resolve against this
        // library. `pubkey.cpp` itself requires only the recovery module.
        .define("ENABLE_MODULE_ECDH", "1")
        .define("ENABLE_MODULE_ELLSWIFT", "1")
        .define("ENABLE_MODULE_EXTRAKEYS", "1")
        .define("ENABLE_MODULE_MUSIG", "1")
        .define("ENABLE_MODULE_RECOVERY", "1")
        .define("ENABLE_MODULE_SCHNORRSIG", "1")
        // The precomputation parameters that `secp256k1-sys` uses.
        .define("ECMULT_WINDOW_SIZE", "15")
        .define("COMB_BLOCKS", "43")
        .define("COMB_TEETH", "6");

    build
        .file("depend/zcash/src/secp256k1/contrib/lax_der_parsing.c")
        .file("depend/zcash/src/secp256k1/src/precomputed_ecmult_gen.c")
        .file("depend/zcash/src/secp256k1/src/precomputed_ecmult.c")
        .file("depend/zcash/src/secp256k1/src/secp256k1.c")
        .compile("libzcash_script_secp256k1.a");
}

/// Configure the language standard used in the build.
///
/// Configures the appropriate flag based on the compiler that's used.
///
/// This will also enable or disable the `cpp` flag if the standard is for C++. The code determines
/// this based on whether `std` starts with `c++` or not.
fn language_std(build: &mut cc::Build, std: &str) {
    build.cpp(std.starts_with("c++"));

    let flag = if build.get_compiler().is_like_msvc() {
        "/std:"
    } else {
        "-std="
    };

    build.flag([flag, std].concat());
}
