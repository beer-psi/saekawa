use snafu::{prelude::*, Whatever};
use vergen::EmitBuilder;

pub fn main() -> Result<(), Whatever> {
    EmitBuilder::builder()
        .build_timestamp()
        .git_sha(false)
        .git_branch()
        .emit()
        .with_whatever_context(|_| "Could not emit version information")?;

    // This makes it possible to write function pointers to the .rtext section.
    // Otherwise, the hook crashes. This is obviously MSVC specific, but who uses
    // i686-pc-windows-gnu anyways.
    if std::env::var("TARGET").unwrap().ends_with("msvc") {
        println!("cargo::rustc-link-arg=/SECTION:.rtext,RW");
    } else {
        println!("cargo::warning=You're not using MSVC. The hook's .rtext section will not be writable, which will cause a crash when performing a self-update.");
    }

    Ok(())
}
