//! Export analytical native compression counts for every requested leaf width.
//!
//! Run `cargo run --locked --offline --example compression_counts` and redirect
//! stdout to a CSV file. This evaluates the library's cost model, not timings.

use std::io::{self, BufWriter, Write};

use binary_merkle_tree::{Blake3, Error, LeafMode, LeafPlan, ResearchHash, Sha3_256, Sha256};

fn export<H: ResearchHash>(
    output: &mut impl Write,
    hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for width_log in 0..=14 {
        let elements_per_leaf = 1_usize << width_log;
        let leaf_bytes = elements_per_leaf * size_of::<u32>();
        let standard_leaf_calls =
            LeafPlan::new::<H>(LeafMode::Standard, leaf_bytes)?.native_calls::<H>();
        for mode in [
            LeafMode::Standard,
            LeafMode::T5,
            LeafMode::T8,
            LeafMode::Abr3,
            LeafMode::T253,
        ] {
            let plan = match LeafPlan::new::<H>(mode, leaf_bytes) {
                Ok(plan) => plan,
                Err(Error::UnsupportedMode) => continue,
                Err(error) => return Err(error.into()),
            };
            let native_leaf_calls = plan.native_calls::<H>();
            let relative_calls = native_leaf_calls as f64 / standard_leaf_calls as f64;
            let calls_saved = i128::from(standard_leaf_calls) - i128::from(native_leaf_calls);
            let saving_percent = 100.0 * calls_saved as f64 / standard_leaf_calls as f64;
            let standard_fallback = mode == LeafMode::T253 && plan.abstract_calls() == 0;
            writeln!(
                output,
                "{hash},{},{},{elements_per_leaf},{leaf_bytes},{native_leaf_calls},{standard_leaf_calls},{relative_calls:.12},{calls_saved},{saving_percent:.12},{standard_fallback}",
                H::PRIMITIVE_NAME,
                mode.name(),
            )?;
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = BufWriter::new(io::stdout().lock());
    writeln!(
        output,
        "hash,primitive,scheme,elements_per_leaf,leaf_bytes,native_leaf_calls,standard_leaf_calls,relative_calls,calls_saved,saving_percent,standard_fallback"
    )?;
    export::<Sha256>(&mut output, "sha256")?;
    export::<Sha3_256>(&mut output, "sha3_256")?;
    export::<Blake3>(&mut output, "blake3")?;
    output.flush()?;
    Ok(())
}
