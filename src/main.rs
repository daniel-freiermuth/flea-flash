use clap::Parser;
use fleascope_rs::{FleaConnector, FleaConnectorError, FlashProgress, FlashUpgradeError};
use std::path::PathBuf;
use thiserror::Error;

// ──────────────────────────────────────────────────────────────────────────────
// CLI
// ──────────────────────────────────────────────────────────────────────────────

/// Flash firmware to a `FleaScope` device via its built-in `upgrade` command.
///
/// The tool validates the Intel HEX file, establishes a working serial
/// connection, and streams the HEX records to the device.  After the last
/// record the device programs its own flash and resets.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Path to the Intel HEX firmware file.
    hex_file: PathBuf,

    /// Serial port to use (e.g. `/dev/ttyACM0`).
    /// Auto-detected if omitted.
    #[arg(short, long)]
    port: Option<String>,

    /// Device name to match during auto-detection (e.g. `FleaScope`).
    /// Ignored when `--port` is given.
    #[arg(short, long)]
    name: Option<String>,

    /// Enable verbose (debug) logging.
    #[arg(short, long)]
    verbose: bool,
}

// ──────────────────────────────────────────────────────────────────────────────
// Intel HEX validation
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
enum HexError {
    #[error("Line {line}: does not start with ':'")]
    MissingStartCode { line: usize },

    #[error("Line {line}: odd number of hex digits")]
    OddLength { line: usize },

    #[error("Line {line}: invalid hex digit")]
    InvalidHex { line: usize },

    #[error("Line {line}: byte count ({declared}) does not match actual data length ({actual})")]
    ByteCountMismatch {
        line: usize,
        declared: usize,
        actual: usize,
    },

    #[error("Line {line}: checksum mismatch (expected 0x{expected:02x}, got 0x{actual:02x})")]
    BadChecksum {
        line: usize,
        expected: u8,
        actual: u8,
    },

    #[error("Line {line}: data record byte count {count} is not a multiple of 4 (firmware requirement)")]
    UnalignedDataCount { line: usize, count: usize },

    #[error("No extended linear address record (type 4) found; firmware requires at least one")]
    MissingExtendedAddress,

    #[error("No EOF record (type 1) found")]
    MissingEof,
}

/// A parsed and validated Intel HEX file, ready to be streamed to the device.
struct HexFile {
    /// Non-empty, trimmed record lines (each starts with `:`).
    lines: Vec<String>,
}

impl HexFile {
    fn load(path: &std::path::Path) -> Result<Self, AppError> {
        let content =
            std::fs::read_to_string(path).map_err(|e| AppError::ReadFile(path.to_owned(), e))?;
        Self::parse(&content).map_err(AppError::HexValidation)
    }

    fn parse(content: &str) -> Result<Self, HexError> {
        let mut lines = Vec::new();
        let mut has_extended_address = false;
        let mut has_eof = false;

        for (raw_line_idx, raw_line) in content.lines().enumerate() {
            let line_num = raw_line_idx + 1; // 1-based for error messages
            let trimmed = raw_line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let record_type = Self::validate_record(trimmed, line_num)?;
            match record_type {
                0x01 => has_eof = true,
                0x04 => has_extended_address = true,
                _ => {}
            }
            lines.push(trimmed.to_string());
        }

        if !has_extended_address {
            return Err(HexError::MissingExtendedAddress);
        }
        if !has_eof {
            return Err(HexError::MissingEof);
        }

        Ok(Self { lines })
    }

    /// Validates one `:LLAAAATTDD...CC` record.  Returns the record type byte.
    fn validate_record(line: &str, line_num: usize) -> Result<u8, HexError> {
        if !line.starts_with(':') {
            return Err(HexError::MissingStartCode { line: line_num });
        }

        let hex_digits = &line[1..];
        if !hex_digits.len().is_multiple_of(2) {
            return Err(HexError::OddLength { line: line_num });
        }

        let bytes: Vec<u8> = hex_digits
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let hi = hex_nibble(pair[0]).ok_or(())?;
                let lo = hex_nibble(pair[1]).ok_or(())?;
                Ok(hi << 4 | lo)
            })
            .collect::<Result<_, ()>>()
            .map_err(|()| HexError::InvalidHex { line: line_num })?;

        // Minimum: 1 (count) + 2 (addr) + 1 (type) + 1 (checksum) = 5 bytes
        if bytes.len() < 5 {
            return Err(HexError::ByteCountMismatch {
                line: line_num,
                declared: 0,
                actual: 0,
            });
        }

        let declared_count = bytes[0] as usize;
        let record_type = bytes[3];
        let data = &bytes[4..bytes.len() - 1];
        let checksum = *bytes.last().expect("checked length above");

        if data.len() != declared_count {
            return Err(HexError::ByteCountMismatch {
                line: line_num,
                declared: declared_count,
                actual: data.len(),
            });
        }

        // Firmware flashes 4 bytes at a time; data records must be 4-byte aligned.
        if record_type == 0x00 && !declared_count.is_multiple_of(4) {
            return Err(HexError::UnalignedDataCount {
                line: line_num,
                count: declared_count,
            });
        }

        // Checksum: two's complement of the sum of all bytes excluding the checksum itself.
        let sum: u8 = bytes[..bytes.len() - 1]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        let expected = (!sum).wrapping_add(1);
        if expected != checksum {
            return Err(HexError::BadChecksum {
                line: line_num,
                expected,
                actual: checksum,
            });
        }

        Ok(record_type)
    }
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Application error
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
enum AppError {
    #[error("Cannot read '{0}': {1}")]
    ReadFile(PathBuf, std::io::Error),

    #[error("Invalid HEX file: {0}")]
    HexValidation(HexError),

    #[error("Connection error: {0}")]
    Connect(#[from] FleaConnectorError),

    #[error("Flash upgrade error: {0}")]
    Flash(#[from] FlashUpgradeError),
}

// ──────────────────────────────────────────────────────────────────────────────
// Entry point
// ──────────────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let log_level = if cli.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    if let Err(e) = run(&cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<(), AppError> {
    // ── 1. Validate HEX file ─────────────────────────────────────────────────
    eprintln!("Validating '{}'...", cli.hex_file.display());
    let hex = HexFile::load(&cli.hex_file)?;
    eprintln!(
        "  OK — {} records",
        hex.lines.len()
    );

    // ── 2. Connect to device ─────────────────────────────────────────────────
    eprintln!("Connecting to device...");
    let mut terminal = FleaConnector::connect(cli.name.as_deref(), cli.port.as_deref(), false)?;
    eprintln!("  Connected.");

    // ── 3. Flash ─────────────────────────────────────────────────────────────
    let record_refs: Vec<&str> = hex.lines.iter().map(String::as_str).collect();
    let total = record_refs.len();

    eprintln!("Flashing {total} records...");

    terminal.flash_upgrade(&record_refs, |progress: FlashProgress| {
        // Print a progress dot every 64 records so the output isn't flooded.
        if progress.sent.is_multiple_of(64) || progress.sent == progress.total {
            let pct = progress.sent * 100 / progress.total;
            eprint!("\r  {}/{} ({pct}%)   ", progress.sent, progress.total);
        }
    })?;

    eprintln!("\r  {total}/{total} (100%)   ");
    eprintln!("Flash complete. Device is resetting — reconnect after a moment.");

    Ok(())
}
