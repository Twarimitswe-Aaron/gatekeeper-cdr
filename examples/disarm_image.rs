/// Gatekeeper CDR Engine — CLI example driver
///
/// Usage:
///   cargo run --example disarm_image -- <input_file> [output_file]
///
/// Examples:
///   cargo run --example disarm_image -- photo.jpg
///   cargo run --example disarm_image -- suspicious.jpg clean.png
///   cargo run --example disarm_image -- image.png sanitized.png

use gatekeeper::{disarm, sniff_format};
use std::{env, fs, path::Path, process};

/// Maximum file size the CLI will read into memory.
///
/// Mirrors the library-level `MAX_COMPRESSED_BYTES` in the sanitizer modules.
/// A file larger than this is rejected before `fs::read` allocates anything.
const MAX_COMPRESSED_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB


fn main() {
    // ── Parse CLI args ────────────────────────────────────────────────────
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <input_file> [output_file]", args[0]);
        eprintln!("Example: cargo run --example disarm_image -- photo.jpg");
        process::exit(1);
    }

    let input_path = Path::new(&args[1]);
    let output_path = args
        .get(2)
        .map(|s| s.as_str().to_owned())
        .unwrap_or_else(|| {
            // Default: same name, .sanitized.png suffix
            let stem = input_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy();
            format!("{stem}.sanitized.png")
        });

    // ── Read input ────────────────────────────────────────────────────────
    println!("▶ Reading  : {}", input_path.display());

    // Check the on-disk file size BEFORE reading the whole file into memory.
    // This prevents a multi-GiB malicious upload from exhausting RAM before
    // the library's PayloadTooLarge guard can fire.
    let file_size = match fs::metadata(input_path) {
        Ok(m) => m.len(),
        Err(e) => {
            eprintln!("✗ Failed to stat file: {e}");
            process::exit(1);
        }
    };

    if file_size > MAX_COMPRESSED_BYTES {
        eprintln!(
            "✗ File too large: {} bytes ({:.2} MiB). Maximum is {} bytes ({:.2} MiB).",
            file_size,
            file_size as f64 / (1024.0 * 1024.0),
            MAX_COMPRESSED_BYTES,
            MAX_COMPRESSED_BYTES as f64 / (1024.0 * 1024.0),
        );
        process::exit(1);
    }

    let raw_bytes = match fs::read(input_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("✗ Failed to read file: {e}");
            process::exit(1);
        }
    };

    println!("  Size     : {} bytes ({:.2} KB)", raw_bytes.len(), raw_bytes.len() as f64 / 1024.0);

    // ── Sniff format (preview, non-destructive) ───────────────────────────
    match sniff_format(&raw_bytes) {
        Ok(fmt) => println!("  Format   : {fmt:?}"),
        Err(e) => {
            eprintln!("✗ Format detection failed: {e}");
            process::exit(1);
        }
    }

    // ── Run CDR pipeline ──────────────────────────────────────────────────
    println!("▶ Disarming...");

    let sanitized = match disarm(&raw_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("✗ CDR pipeline failed: {e}");
            process::exit(1);
        }
    };

    // External callers extract bytes via the public into_bytes() method.
    // The formal `let SanitizedOutput(bytes) = ...` destructure is reserved
    // for code inside the crate (e.g. a save_to_storage fn in the lib).
    let clean_bytes = sanitized.into_bytes();

    println!("  Output   : {} bytes ({:.2} KB)", clean_bytes.len(), clean_bytes.len() as f64 / 1024.0);

    // ── Write output ──────────────────────────────────────────────────────
    println!("▶ Writing  : {output_path}");

    if let Err(e) = fs::write(&output_path, &clean_bytes) {
        eprintln!("✗ Failed to write output: {e}");
        process::exit(1);
    }

    println!("✔ Done. Sanitized PNG written to: {output_path}");
}
