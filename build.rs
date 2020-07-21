use color_eyre::eyre::{eyre, Context, Result};
use std::{env, path::PathBuf};

fn bindgen_headers() -> Result<()> {
    println!("cargo:rerun-if-changed=depend/zcash/src/script/zcashconsensus.h");

    let bindings = bindgen::Builder::default()
        .header("depend/zcash/src/script/zcashconsensus.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        .map_err(|_| eyre!("Unable to generate bindings"))?;

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = env::var("OUT_DIR")?;
    let out_path = PathBuf::from(out_path);
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .wrap_err("unable to write bindings")?;

    Ok(())
}

fn main() -> Result<()> {
    color_eyre::install()?;

    bindgen_headers()?;

    // Check whether we can use 64-bit compilation
    let use_64bit_compilation = if env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap() == "64" {
        let check = cc::Build::new()
            .file("depend/check_uint128_t.c")
            .cargo_metadata(false)
            .try_compile("check_uint128_t")
            .is_ok();
        if !check {
            println!("cargo:warning=Compiling in 32-bit mode on a 64-bit architecture due to lack of uint128_t support.");
        }
        check
    } else {
        false
    };
    let target = env::var("TARGET").expect("TARGET was not set");
    let is_big_endian = env::var("CARGO_CFG_TARGET_ENDIAN").expect("No endian is set") == "big";
    let mut base_config = cc::Build::new();

    base_config
        .cpp(true)
        .include("depend/zcash/src")
        .include("depend/zcash/src/rust/include/")
        .include("depend/zcash/src/secp256k1/include")
        .flag_if_supported("-Wno-implicit-fallthrough")
        .flag_if_supported("-Wno-catch-value")
        .flag_if_supported("-Wno-reorder")
        .flag_if_supported("-Wno-deprecated-copy")
        .define("HAVE_DECL_STRNLEN", "1")
        .define("__STDC_FORMAT_MACROS", None);

    // **Secp256k1**
    if !cfg!(feature = "external-secp") {
        base_config
            .include("depend/zcash/src/secp256k1")
            .flag_if_supported("-Wno-unused-function") // some ecmult stuff is defined but not used upstream
            .define("SECP256K1_BUILD", "1")
            // zcash core defines libsecp to *not* use libgmp.
            .define("USE_NUM_NONE", "1")
            .define("USE_FIELD_INV_BUILTIN", "1")
            .define("USE_SCALAR_INV_BUILTIN", "1")
            // Technically libconsensus doesn't require the recovery feautre, but `pubkey.cpp` does.
            .define("ENABLE_MODULE_RECOVERY", "1")
            // The actual libsecp256k1 C code.
            .file("depend/zcash/src/secp256k1/src/secp256k1.c");

        if is_big_endian {
            base_config.define("WORDS_BIGENDIAN", "1");
        }

        if use_64bit_compilation {
            base_config
                .define("USE_FIELD_5X52", "1")
                .define("USE_SCALAR_4X64", "1")
                .define("HAVE___INT128", "1");
        } else {
            base_config
                .define("USE_FIELD_10X26", "1")
                .define("USE_SCALAR_8X32", "1");
        }
    }

    let tool = base_config.get_compiler();
    if tool.is_like_msvc() {
        base_config.flag("/std:c++17").flag("/wd4100");
    } else if tool.is_like_clang() || tool.is_like_gnu() {
        base_config.flag("-std=c++17").flag("-Wno-unused-parameter");
    }

    if target.contains("windows") {
        base_config.define("WIN32", "1");
    }

    base_config
        .file("depend/zcash/src/script/zcashconsensus.cpp")
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
        .compile("libzcashconsensus.a");

    Ok(())
}
