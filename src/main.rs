use clap::Parser;
use fleascope_rs::{
    FlashProgress, FlashUpgradeError, FleaConnector, FleaConnectorError, FleaDevice,
    FleaTerminalError, IdleFleaTerminal, StatelessFleaTerminal,
};
use std::io::Write as _;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
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

    /// Device name to match (e.g. `FleaScope`).
    /// Combined with `--port` when both are given.
    #[arg(short, long)]
    name: Option<String>,

    /// Skip the interactive confirmation prompt (for scripted use).
    #[arg(short, long)]
    yes: bool,

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

    #[error("Line {line}: record too short ({len} bytes, minimum 5)")]
    RecordTooShort { line: usize, len: usize },

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

    #[error(
        "Line {line}: data record byte count {count} is not a multiple of 4 (firmware requirement)"
    )]
    UnalignedDataCount { line: usize, count: usize },

    #[error("Line {line}: data record address 0x{address:04x} is not 4-byte aligned (firmware requirement)")]
    UnalignedDataAddress { line: usize, address: u16 },

    #[error(
        "Line {line}: record type 0x{record_type:02x} with {count} data bytes is not accepted by the firmware (only 00, 01 with 0 bytes, 04 with 2 bytes)"
    )]
    UnsupportedRecord {
        line: usize,
        record_type: u8,
        count: usize,
    },

    #[error(
        "Line {line}: record is {len} characters; the firmware's terminal keeps only {MAX_RECORD_LINE_LEN} per line (at most 28 data bytes per record)"
    )]
    LineTooLong { line: usize, len: usize },

    #[error("No extended linear address record (type 4) found; firmware requires at least one")]
    MissingExtendedAddress,

    #[error("Line {line}: data record before the first extended linear address record (type 4); firmware would write it to an undefined address")]
    DataBeforeExtendedAddress { line: usize },

    #[error("No EOF record (type 1) found")]
    MissingEof,

    #[error(
        "Line {line}: record after EOF record (type 1); the device stops reading at the first EOF"
    )]
    DataAfterEof { line: usize },
}

/// Longest line the firmware's terminal accepts: `command[BASIC_INPUT_LINE_SIZE]`
/// (72) minus the NUL; extra characters are silently dropped (terminal.c).
const MAX_RECORD_LINE_LEN: usize = 71;

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

            if has_eof {
                return Err(HexError::DataAfterEof { line: line_num });
            }

            let record_type = Self::validate_record(trimmed, line_num)?;
            match record_type {
                0x00 if !has_extended_address => {
                    // Firmware (flash.c) leaves `extend` uninitialized until the
                    // first 04 record, so earlier data would go to a garbage address.
                    return Err(HexError::DataBeforeExtendedAddress { line: line_num });
                }
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

        if line.len() > MAX_RECORD_LINE_LEN {
            return Err(HexError::LineTooLong {
                line: line_num,
                len: line.len(),
            });
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
            return Err(HexError::RecordTooShort {
                line: line_num,
                len: bytes.len(),
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

        // Firmware (flash.c) accepts only data (00), EOF (01, 0 bytes) and
        // extended linear address (04, 2 bytes); anything else is "bad record".
        match (record_type, declared_count) {
            (0x00, _) | (0x01, 0) | (0x04, 2) => {}
            _ => {
                return Err(HexError::UnsupportedRecord {
                    line: line_num,
                    record_type,
                    count: declared_count,
                });
            }
        }

        // Firmware flashes 4 bytes at a time; data records must be 4-byte aligned.
        if record_type == 0x00 && !declared_count.is_multiple_of(4) {
            return Err(HexError::UnalignedDataCount {
                line: line_num,
                count: declared_count,
            });
        }
        // It does 32-bit loads/writes at extend<<16 | address; the type-04
        // record only supplies the upper half, so the address must be aligned.
        let address = u16::from_be_bytes([bytes[1], bytes[2]]);
        if record_type == 0x00 && !address.is_multiple_of(4) {
            return Err(HexError::UnalignedDataAddress {
                line: line_num,
                address,
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

    #[error(
        "Multiple matching devices found — use --port to select one:\n{}",
        .0.iter().map(|d| format!("  {} on {}", d.name, d.port)).collect::<Vec<_>>().join("\n")
    )]
    AmbiguousDevice(Vec<FleaDevice>),

    #[error("I/O error reading confirmation: {0}")]
    ConfirmIo(#[from] std::io::Error),

    #[error("Aborted by user.")]
    Aborted,
}

/// A `FleaScope` port as enumerated, with the device's USB serial number.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PortCandidate {
    port: String,
    serial: Option<String>,
}

/// Enumerate `FleaScope` ports (any product name) with their USB serial numbers.
fn enumerate_fleascopes() -> Result<Vec<PortCandidate>, AppError> {
    let flea_ports: Vec<String> = FleaConnector::get_available_devices(None)?
        .map(|d| d.port)
        .collect();
    let ports = serialport::available_ports().map_err(FleaConnectorError::from)?;
    Ok(ports
        .into_iter()
        .filter(|p| flea_ports.contains(&p.port_name))
        .map(|p| PortCandidate {
            serial: match p.port_type {
                serialport::SerialPortType::UsbPort(usb) => usb.serial_number,
                _ => None,
            },
            port: p.port_name,
        })
        .collect())
}

/// Handshake attempts of `connect_port`, as in fleascope-rs; all but the last
/// one end in a `reset` when the device does not answer in time.
const CONNECT_ATTEMPTS: usize = 3;

/// Open the `confirmed` port and bring it to an idle terminal.
///
/// Mirrors `FleaConnector`'s name-based connect: on a handshake timeout it
/// sends `reset`, closes the port, waits, and enumerates again (`enumerate`),
/// because the rebooted device can come back under a different port. After
/// `CONNECT_ATTEMPTS` timed-out handshakes the timeout is returned. The
/// device is found by USB serial number, never by product name, before the
/// first open as well as after each reset, so the device that gets flashed is
/// the one the user confirmed even if another took its port meanwhile.
fn connect_port(
    name: &str,
    confirmed: &PortCandidate,
    mut enumerate: impl FnMut() -> Result<Vec<PortCandidate>, AppError>,
) -> Result<IdleFleaTerminal, AppError> {
    let find = |found: &[PortCandidate]| {
        reselect_port(confirmed, found).ok_or_else(|| FleaConnectorError::DeviceNotFound {
            name: name.to_string(),
        })
    };
    let mut port = find(&enumerate()?)?;
    let mut attempt = 1;
    loop {
        match StatelessFleaTerminal::new(&port)
            .map_err(FleaConnectorError::from)?
            .try_into()
        {
            Ok(terminal) => return Ok(terminal),
            Err((mut serial, FleaTerminalError::Timeout { .. })) if attempt < CONNECT_ATTEMPTS => {
                log::debug!("Timeout during initialization, sending reset and retrying");
                // Best effort, as in fleascope-rs: still retry, but surface why.
                if let Err(e) = serial.send_reset() {
                    log::warn!("sending reset to {port} failed: {e}");
                }
                // Release the port so the re-enumerated device is not kept
                // off its old device node.
                drop(serial);
                thread::sleep(Duration::from_secs(2));
                port = find(&enumerate()?)?;
                attempt += 1;
            }
            Err((_serial, e)) => return Err(FleaConnectorError::from(e).into()),
        }
    }
}

/// Find the `confirmed` device among `found`.
///
/// Identity is the USB serial number; among several ports of that device
/// (macOS lists `/dev/cu.*` and `/dev/tty.*`) the confirmed port is preferred.
/// Without a serial number only the confirmed port itself is accepted.
/// `None` means the confirmed device is not present.
fn reselect_port(confirmed: &PortCandidate, found: &[PortCandidate]) -> Option<String> {
    let same_device: Vec<&PortCandidate> = found
        .iter()
        .filter(|c| {
            confirmed.serial.as_ref().map_or_else(
                || c.port == confirmed.port,
                |serial| c.serial.as_ref() == Some(serial),
            )
        })
        .collect();
    same_device
        .iter()
        .find(|c| c.port == confirmed.port)
        .or_else(|| same_device.first())
        .map(|c| c.port.clone())
}

/// Pick the single device to flash from `devices`, narrowed to `port` if given.
///
/// macOS lists each device twice, as `/dev/cu.*` and `/dev/tty.*`; the
/// `tty.*` alias of a listed `cu.*` port is dropped so one device stays one.
fn select_device(
    mut devices: Vec<FleaDevice>,
    port: Option<&str>,
    name: Option<&str>,
) -> Result<FleaDevice, AppError> {
    // Narrow to the requested port when --port is given.
    if let Some(port) = port {
        devices.retain(|d| d.port == port);
        if devices.is_empty() {
            return Err(FleaConnectorError::InvalidPort {
                port: port.to_string(),
            }
            .into());
        }
    }

    // Drop `tty.*` dial-in aliases whose `cu.*` callout twin is listed.
    let ports: Vec<String> = devices.iter().map(|d| d.port.clone()).collect();
    devices.retain(|d| {
        d.port
            .strip_prefix("/dev/tty.")
            .is_none_or(|rest| !ports.contains(&format!("/dev/cu.{rest}")))
    });

    match devices.len() {
        0 => Err(FleaConnectorError::DeviceNotFound {
            name: name.unwrap_or("FleaScope").to_string(),
        }
        .into()),
        1 => Ok(devices.remove(0)),
        _ => Err(AppError::AmbiguousDevice(devices)),
    }
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
    eprintln!("  OK — {} records", hex.lines.len());

    // ── 2. Enumerate and select device ───────────────────────────────────────
    // Collect every device that matches the optional --name filter.
    let devices: Vec<FleaDevice> =
        FleaConnector::get_available_devices(cli.name.as_deref())?.collect();
    let device = &select_device(devices, cli.port.as_deref(), cli.name.as_deref())?;
    // Record the device's USB serial number now, so connecting can check it is
    // still this device and find it again if it re-enumerates under another port.
    let confirmed = enumerate_fleascopes()?
        .into_iter()
        .find(|c| c.port == device.port)
        .unwrap_or_else(|| PortCandidate {
            port: device.port.clone(),
            serial: None,
        });

    // ── 3. Confirm with the user ─────────────────────────────────────────────
    eprintln!("Target device: {} on {}", device.name, device.port);

    if !cli.yes {
        eprint!("Flash this device? [y/N] ");
        std::io::stderr().flush()?;

        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        match answer.trim().to_lowercase().as_str() {
            "y" | "yes" => {}
            _ => return Err(AppError::Aborted),
        }
    }

    // ── 4. Connect ───────────────────────────────────────────────────────────
    eprintln!("Connecting...");
    // Connect to the confirmed device, with the library's reset-and-retry on
    // handshake timeout (FleaConnector::connect with Some(port) panics on it).
    let mut terminal = connect_port(&device.name, &confirmed, enumerate_fleascopes)?;
    eprintln!("  Connected.");

    // ── 5. Flash ─────────────────────────────────────────────────────────────
    let record_refs: Vec<&str> = hex.lines.iter().map(String::as_str).collect();
    let total = record_refs.len();

    eprintln!("Flashing {total} records...");

    terminal.flash_upgrade(&record_refs, |progress: FlashProgress| {
        if progress.sent.is_multiple_of(64) || progress.sent == progress.total {
            let pct = progress.sent * 100 / progress.total;
            eprint!("\r  {}/{} ({pct}%)   ", progress.sent, progress.total);
        }
    })?;

    eprintln!("\r  {total}/{total} (100%)   ");
    eprintln!("Flash complete. Device is resetting — reconnect after a moment.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(port: &str, serial: Option<&str>) -> PortCandidate {
        PortCandidate {
            port: port.to_string(),
            serial: serial.map(str::to_string),
        }
    }

    #[test]
    fn parse_rejects_records_firmware_cannot_accept() {
        // Type-05 start linear address (emitted by GNU objcopy): firmware says "bad record".
        assert!(matches!(
            HexFile::parse(":020000040000FA\n:04000005BFC0000078\n:00000001FF\n"),
            Err(HexError::UnsupportedRecord {
                line: 2,
                record_type: 0x05,
                count: 4
            })
        ));
        // Type-04 must carry exactly 2 bytes.
        assert!(matches!(
            HexFile::parse(":0400000400000000F8\n:00000001FF\n"),
            Err(HexError::UnsupportedRecord {
                line: 1,
                record_type: 0x04,
                count: 4
            })
        ));
        // Type-01 must carry no data.
        assert!(matches!(
            HexFile::parse(":020000040000FA\n:0100000100FE\n"),
            Err(HexError::UnsupportedRecord {
                line: 2,
                record_type: 0x01,
                count: 1
            })
        ));
        assert!(HexFile::parse(":020000040000FA\n:0400000001020304F2\n:00000001FF\n").is_ok());
    }

    #[test]
    fn parse_reports_truncated_record_as_too_short() {
        let err = HexFile::parse(":020000040000FA\n:04000000\n:00000001FF\n").err();
        assert_eq!(
            err.map(|e| e.to_string()).as_deref(),
            Some("Line 2: record too short (4 bytes, minimum 5)")
        );
    }

    #[test]
    fn parse_rejects_unaligned_data_address() {
        // Firmware does 32-bit loads/writes at extend<<16 | addr; addr 0x0002 is unaligned.
        assert!(matches!(
            HexFile::parse(":020000040000FA\n:0400020001020304F0\n:00000001FF\n"),
            Err(HexError::UnalignedDataAddress {
                line: 2,
                address: 0x0002
            })
        ));
        assert!(HexFile::parse(":020000040000FA\n:0400040001020304EE\n:00000001FF\n").is_ok());
    }

    #[test]
    fn parse_reports_corrupted_type_or_address_as_checksum_mismatch() {
        // Valid data record ":0400000001020304F2" with the type byte flipped to 05.
        assert!(matches!(
            HexFile::parse(":020000040000FA\n:0400000501020304F2\n:00000001FF\n"),
            Err(HexError::BadChecksum { line: 2, .. })
        ));
        // Same record with the address flipped to 0x0002.
        assert!(matches!(
            HexFile::parse(":020000040000FA\n:0400020001020304F2\n:00000001FF\n"),
            Err(HexError::BadChecksum { line: 2, .. })
        ));
    }

    #[test]
    fn parse_rejects_records_longer_than_device_line_buffer() {
        // 28 data bytes = 67 characters: fits the firmware's 71-character command line.
        assert!(HexFile::parse(
            ":020000040000FA\n:1C00000000000000000000000000000000000000000000000000000000000000E4\n:00000001FF\n"
        )
        .is_ok());
        // 32 data bytes = 75 characters: the device would truncate it after erasing flash.
        assert!(matches!(
            HexFile::parse(
                ":020000040000FA\n:200000000000000000000000000000000000000000000000000000000000000000000000E0\n:00000001FF\n"
            ),
            Err(HexError::LineTooLong { line: 2, len: 75 })
        ));
    }

    #[test]
    fn parse_rejects_data_before_first_extended_address() {
        // Firmware's `extend` is uninitialized until the first 04 record, so
        // data placed before it lands at a garbage address.
        assert!(matches!(
            HexFile::parse(":0400000001020304F2\n:020000040000FA\n:00000001FF\n"),
            Err(HexError::DataBeforeExtendedAddress { line: 1 })
        ));
    }

    #[test]
    fn reselect_port_follows_serial_to_new_port() {
        let confirmed = cand("/dev/ttyACM0", Some("A"));
        let found = [
            cand("/dev/ttyACM1", Some("B")),
            cand("/dev/ttyACM2", Some("A")),
        ];
        assert_eq!(
            reselect_port(&confirmed, &found).as_deref(),
            Some("/dev/ttyACM2")
        );
    }

    #[test]
    fn reselect_port_never_picks_another_device() {
        // The confirmed device is not back yet; another FleaScope (same
        // product name, different serial) must not be selected.
        let confirmed = cand("/dev/ttyACM0", Some("A"));
        let found = [cand("/dev/ttyACM1", Some("B"))];
        assert_eq!(reselect_port(&confirmed, &found), None);
    }

    #[test]
    fn reselect_port_prefers_confirmed_port_among_aliases() {
        // macOS lists one device twice (cu.* and tty.*) with the same serial.
        let confirmed = cand("/dev/tty.usbmodem1", Some("A"));
        let found = [
            cand("/dev/cu.usbmodem1", Some("A")),
            cand("/dev/tty.usbmodem1", Some("A")),
        ];
        assert_eq!(
            reselect_port(&confirmed, &found).as_deref(),
            Some("/dev/tty.usbmodem1")
        );
    }

    #[test]
    fn reselect_port_without_serial_accepts_only_confirmed_port() {
        let confirmed = cand("/dev/ttyACM0", None);
        assert_eq!(
            reselect_port(&confirmed, &[cand("/dev/ttyACM1", None)]),
            None
        );
        assert_eq!(
            reselect_port(&confirmed, &[cand("/dev/ttyACM0", None)]).as_deref(),
            Some("/dev/ttyACM0")
        );
    }

    fn dev(port: &str) -> FleaDevice {
        FleaDevice {
            name: "FleaScope".to_string(),
            port: port.to_string(),
        }
    }

    #[test]
    fn select_device_treats_macos_cu_and_tty_as_one_device() {
        // macOS lists one device twice: callout (cu.*) and dial-in (tty.*).
        let aliases = || vec![dev("/dev/cu.usbmodem1"), dev("/dev/tty.usbmodem1")];
        let picked = select_device(aliases(), None, None).map(|d| d.port);
        assert_eq!(picked.ok().as_deref(), Some("/dev/cu.usbmodem1"));
        // An explicit --port still selects either alias.
        let picked = select_device(aliases(), Some("/dev/tty.usbmodem1"), None).map(|d| d.port);
        assert_eq!(picked.ok().as_deref(), Some("/dev/tty.usbmodem1"));
        // Two distinct devices stay ambiguous.
        let two = vec![dev("/dev/cu.usbmodem1"), dev("/dev/cu.usbmodem2")];
        assert!(matches!(
            select_device(two, None, None),
            Err(AppError::AmbiguousDevice(_))
        ));
    }

    /// Fake device on a pty master: records what it receives and, if
    /// `answers`, replies with the prompt to `prompt on`.
    #[cfg(unix)]
    fn fake_device(
        mut master: serialport::TTYPort,
        answers: bool,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> thread::JoinHandle<String> {
        use std::io::Read as _;
        thread::spawn(move || {
            let mut seen = Vec::new();
            let mut buf = [0u8; 64];
            let mut answered = false;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                match master.read(&mut buf) {
                    Ok(n) if n > 0 => seen.extend_from_slice(&buf[..n]),
                    _ => thread::sleep(Duration::from_millis(10)),
                }
                if answers && !answered && seen.ends_with(b"prompt on\n") {
                    master.write_all(b"> ").unwrap();
                    answered = true;
                }
            }
            String::from_utf8_lossy(&seen).into_owned()
        })
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "macOS ptys reject the IOSSIOSPEED ioctl serialport uses to set the baud rate on open"
    )]
    fn connect_port_resets_and_follows_confirmed_device_to_new_port() {
        use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

        let pty = || {
            let (master, slave) = serialport::TTYPort::pair().unwrap();
            let path = serialport::SerialPort::name(&slave).unwrap();
            (master, slave, path)
        };
        // Old port of the confirmed device: never answers the handshake.
        let (old_master, _old_slave, old_path) = pty();
        // The confirmed device after its reset, under a new port.
        let (new_master, _new_slave, new_path) = pty();
        // Another FleaScope with a different serial number.
        let (other_master, _other_slave, other_path) = pty();

        let stop = Arc::new(AtomicBool::new(false));
        let old = fake_device(old_master, false, Arc::clone(&stop));
        let new = fake_device(new_master, true, Arc::clone(&stop));
        let other = fake_device(other_master, true, Arc::clone(&stop));

        let confirmed = cand(&old_path, Some("A"));
        // Before the reset the confirmed device is on its old port.
        let mut found = vec![cand(&other_path, Some("B")), cand(&old_path, Some("A"))];
        let result = connect_port("Flea-Scope", &confirmed, || {
            let current = found.clone();
            found = vec![cand(&other_path, Some("B")), cand(&new_path, Some("A"))];
            Ok(current)
        });

        stop.store(true, Ordering::SeqCst);
        let (old, new, other) = (
            old.join().unwrap(),
            new.join().unwrap(),
            other.join().unwrap(),
        );
        assert!(result.is_ok(), "connect failed: {:?}", result.err());
        assert!(
            old.contains("prompt on\n") && old.contains("reset\n"),
            "old port saw {old:?}"
        );
        assert!(new.ends_with("prompt on\n"), "new port saw {new:?}");
        assert!(other.is_empty(), "other device was contacted: {other:?}");
    }

    #[cfg(unix)]
    #[test]
    fn connect_port_refuses_other_device_on_confirmed_port() {
        use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

        // The confirmed device (serial A) was unplugged while the prompt
        // waited; another FleaScope (serial B) now owns the same node and
        // would answer the handshake.
        let (master, slave) = serialport::TTYPort::pair().unwrap();
        let path = serialport::SerialPort::name(&slave).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let other = fake_device(master, true, Arc::clone(&stop));

        let confirmed = cand(&path, Some("A"));
        let found = vec![cand(&path, Some("B"))];
        let result = connect_port("Flea-Scope", &confirmed, || Ok(found.clone()));

        stop.store(true, Ordering::SeqCst);
        let other = other.join().unwrap();
        assert!(
            result.is_err(),
            "connected to a device the user did not confirm"
        );
        assert!(other.is_empty(), "other device was contacted: {other:?}");
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "macOS ptys reject the IOSSIOSPEED ioctl serialport uses to set the baud rate on open"
    )]
    fn connect_port_gives_up_when_confirmed_device_never_answers() {
        use std::sync::{atomic::AtomicBool, atomic::Ordering, mpsc, Arc};

        // The confirmed device stays enumerated but never answers the
        // handshake, not even after a reset.
        let (master, slave) = serialport::TTYPort::pair().unwrap();
        let path = serialport::SerialPort::name(&slave).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let device = fake_device(master, false, Arc::clone(&stop));

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let confirmed = cand(&path, Some("A"));
            let mut lookups = 0;
            let result = connect_port("Flea-Scope", &confirmed, || {
                lookups += 1;
                Ok(vec![cand(&path, Some("A"))])
            });
            let _ = tx.send((result.err(), lookups));
        });
        // Each attempt takes about 1s ("prompt on" timeout), each reset 2s.
        let outcome = rx.recv_timeout(Duration::from_secs(30));

        stop.store(true, Ordering::SeqCst);
        let device = device.join().unwrap();
        let (err, lookups) = outcome.expect("connect_port did not give up");
        assert!(
            matches!(
                err,
                Some(AppError::Connect(FleaConnectorError::SerialTerminal(
                    FleaTerminalError::Timeout { .. }
                )))
            ),
            "expected a handshake timeout, got {err:?}"
        );
        assert_eq!(lookups, CONNECT_ATTEMPTS);
        assert!(device.contains("reset\n"), "device saw {device:?}");
    }

    #[test]
    fn rejects_records_after_eof() {
        let concatenated = ":020000040000FA\n:04000000DEADBEEFC4\n:00000001FF\n:020000041D00DD\n:04000000CAFEBABEBC\n:00000001FF\n";
        assert!(matches!(
            HexFile::parse(concatenated),
            Err(HexError::DataAfterEof { line: 4 })
        ));
        let ok = ":020000040000FA\n:04000000DEADBEEFC4\n:00000001FF\n\n";
        assert_eq!(HexFile::parse(ok).unwrap().lines.len(), 3);
    }
}
