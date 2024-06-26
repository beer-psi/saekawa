use snafu::{prelude::*, Whatever};
use vergen::EmitBuilder;

pub fn main() -> Result<(), Whatever> {
    EmitBuilder::builder()
        .build_timestamp()
        .git_sha(false)
        .git_branch()
        .emit()
        .with_whatever_context(|_| "Could not emit version information")?;
    Ok(())
}
