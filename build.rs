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
            Error::GenerateBindings => write!(f, "unable to generate bindings"),
            Error::WriteBindings(source) => write!(f, "unable to write bindings: {}", source),
            Error::Env(source) => source.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

fn bindgen_headers() -> Result<()> {
    println!("cargo:rerun-if-changed=depend/zcash/src/script/zcash_script.h");

    let bindings = bindgen::Builder::default()
        .header("depend/zcash/src/script/zcash_script.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
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
        .include("depend/zcash/src")
        .include("depend/zcash/src/rust/include/")
        .include("depend/zcash/src/secp256k1/include")
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
        .define("__STDC_FORMAT_MACROS", None);

    // **Secp256k1**
    if !cfg!(feature = "external-secp") {
        build_secp256k1();
    }

    if target.contains("windows") {
        base_config.define("WIN32", "1");
    }

    base_config
        .file("depend/zcash/src/script/zcash_script.cpp")
        .file("depend/zcash/src/utilstrencodings.cpp")
        .file("depend/zcash/src/uint256.cpp")
        .file("depend/zcash/src/pubkey.cpp")
        .file("depend/zcash/src/hash.cpp")
        .file("depend/zcash/src/primitives/transaction.cpp")
        .file("depend/zcash/src/crypto/ripemd160.cpp")
        .file("depend/zcash/src/crypto/sha1.cpp")
        .file("depend/zcash/src/crypto/sha256.cpp")
        .file("depend/zcash/src/crypto/sha512.cpp")
        .file("depend/zcash/src/crypto/hmac_sha512.cpp")
        .file("depend/zcash/src/script/interpreter.cpp")
        .file("depend/zcash/src/script/script.cpp")
        .file("depend/zcash/src/script/script_error.cpp")
        .file("depend/zcash/src/support/cleanse.cpp")
        .compile("libzcash_script.a");

    Ok(())
}

/// Build the `secp256k1` library.
fn build_secp256k1() {
    let mut build = cc::Build::new();

    // Compile C99 code
    language_std(&mut build, "c99");

    // Define configuration constants
    build
        .define("SECP256K1_BUILD", "1")
        .define("USE_NUM_NONE", "1")
        .define("USE_FIELD_INV_BUILTIN", "1")
        .define("USE_SCALAR_INV_BUILTIN", "1")
        .define("ECMULT_WINDOW_SIZE", "15")
        .define("ECMULT_GEN_PREC_BITS", "4")
        // Use the endomorphism optimization now that the patents have expired.
        .define("USE_ENDOMORPHISM", "1")
        // Technically libconsensus doesn't require the recovery feature, but `pubkey.cpp` does.
        .define("ENABLE_MODULE_RECOVERY", "1")
        // The source files look for headers inside an `include` sub-directory
        .include("depend/zcash/src/secp256k1")
        // Some ecmult stuff is defined but not used upstream
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-parameter");

    if is_big_endian() {
        build.define("WORDS_BIGENDIAN", "1");
    }

    if is_64bit_compilation() {
        build
            .define("USE_FIELD_5X52", "1")
            .define("USE_SCALAR_4X64", "1")
            .define("HAVE___INT128", "1");
    } else {
        build
            .define("USE_FIELD_10X26", "1")
            .define("USE_SCALAR_8X32", "1");
    }

    build
        .file("depend/zcash/src/secp256k1/src/secp256k1.c")
        .compile("libsecp256k1.a");
}

/// Checker whether the target architecture is big endian.
fn is_big_endian() -> bool {
    let endianess = env::var("CARGO_CFG_TARGET_ENDIAN").expect("No endian is set");

    endianess == "big"
}

/// Check whether we can use 64-bit compilation.
fn is_64bit_compilation() -> bool {
    let target_pointer_width =
        env::var("CARGO_CFG_TARGET_POINTER_WIDTH").expect("Target pointer width is not set");

    if target_pointer_width == "64" {
        let check = cc::Build::new()
            .file("depend/check_uint128_t.c")
            .cargo_metadata(false)
            .try_compile("check_uint128_t")
            .is_ok();

        if !check {
            println!(
                "cargo:warning=Compiling in 32-bit mode on a 64-bit architecture due to lack of \
                uint128_t support."
            );
        }

        check
    } else {
        false
    }
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

    build.flag(&[flag, std].concat());
}
