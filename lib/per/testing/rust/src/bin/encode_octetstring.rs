/// Encode a named OCTET STRING type using rasn (librasn) with APER or UPER.
///
/// Usage:
///   encode-octetstring -name <TypeName> -length <N> [-aligned]
///
/// Flags:
///   -name <TypeName>  ASN.1 type name (e.g. 'OCTETSTRING-NULL-NULL-FALSE')
///   -length <N>       octet string length in bytes
///   -aligned          use APER (aligned PER); omit for UPER (default)
///
/// Output: hex-encoded PER bytes on stdout
///
/// The type names follow the convention: OCTETSTRING-<LB>-<UB>-<EXT>
///   LB:  lower bound or NULL (unconstrained)
///   UB:  upper bound or NULL (semi-constrained / unconstrained)
///   EXT: TRUE (extensible) or FALSE (not extensible)
use rasn::prelude::*;
use rasn::types::OctetString;
use std::env;
use std::process;

// ---------------------------------------------------------------------------
// Type definitions — one per constraint combination
// ---------------------------------------------------------------------------

macro_rules! def_os {
    ($name:ident) => {
        #[derive(AsnType, Encode)]
        #[rasn(delegate)]
        struct $name(OctetString);
    };
    ($name:ident, $range:literal) => {
        #[derive(AsnType, Encode)]
        #[rasn(delegate, size($range))]
        struct $name(OctetString);
    };
}

macro_rules! def_os_ext {
    ($name:ident, $range:literal) => {
        #[derive(AsnType, Encode)]
        #[rasn(delegate, size($range, extensible))]
        struct $name(OctetString);
    };
}

// Unconstrained
def_os!(OsNullNullFalse);

// Semi-constrained (lb only, ub = MAX)
def_os!(Os0NullFalse, "0..");
def_os!(Os10NullFalse, "10..");

// Constrained (lb = 0, various ub), not extensible
def_os!(Os0_2False, "0..=2");
def_os!(Os0_4False, "0..=4");
def_os!(Os0_8False, "0..=8");
def_os!(Os0_10False, "0..=10");
def_os!(Os0_16False, "0..=16");
def_os!(Os0_32False, "0..=32");
def_os!(Os0_64False, "0..=64");
def_os!(Os0_128False, "0..=128");
def_os!(Os0_256False, "0..=256");
def_os!(Os0_512False, "0..=512");
def_os!(Os0_1024False, "0..=1024");
def_os!(Os0_2048False, "0..=2048");
def_os!(Os0_4096False, "0..=4096");
def_os!(Os0_8192False, "0..=8192");
def_os!(Os0_16384False, "0..=16384");
def_os!(Os0_32768False, "0..=32768");
def_os!(Os0_65536False, "0..=65536");
def_os!(Os0_131072False, "0..=131072");
def_os!(Os0_262144False, "0..=262144");
def_os!(Os0_524288False, "0..=524288");
def_os!(Os0_1048576False, "0..=1048576");
def_os!(Os0_2097152False, "0..=2097152");

// Constrained, extensible (lb = 0, various ub)
def_os_ext!(Os0_0True, "0..=0");
def_os_ext!(Os0_1True, "0..=1");
def_os_ext!(Os0_2True, "0..=2");
def_os_ext!(Os0_4True, "0..=4");
def_os_ext!(Os0_8True, "0..=8");
def_os_ext!(Os0_16True, "0..=16");
def_os_ext!(Os0_32True, "0..=32");
def_os_ext!(Os0_64True, "0..=64");
def_os_ext!(Os0_128True, "0..=128");
def_os_ext!(Os0_256True, "0..=256");
def_os_ext!(Os0_512True, "0..=512");
def_os_ext!(Os0_1024True, "0..=1024");
def_os_ext!(Os0_2048True, "0..=2048");
def_os_ext!(Os0_4096True, "0..=4096");
def_os_ext!(Os0_8192True, "0..=8192");
def_os_ext!(Os0_16384True, "0..=16384");
def_os_ext!(Os0_32768True, "0..=32768");
def_os_ext!(Os0_65536True, "0..=65536");
def_os_ext!(Os0_131072True, "0..=131072");
def_os_ext!(Os0_262144True, "0..=262144");
def_os_ext!(Os0_524288True, "0..=524288");

// ---------------------------------------------------------------------------
// Octet pattern generator — repeating 0x00..0xFF (256-byte cycle)
// ---------------------------------------------------------------------------

fn gen_pattern(length: usize) -> OctetString {
    let pattern: Vec<u8> = (0..=255u8).collect();
    let mut buf = Vec::with_capacity(length);
    let mut i = 0;
    while buf.len() < length {
        buf.push(pattern[i % 256]);
        i += 1;
    }
    OctetString::from(buf)
}

// ---------------------------------------------------------------------------
// Encode dispatcher — maps type name string to the appropriate rasn type
// ---------------------------------------------------------------------------

fn encode_octetstring(name: &str, value: OctetString, aligned: bool) -> Result<Vec<u8>, String> {
    macro_rules! enc {
        ($ty:ident) => {{
            let v = $ty(value);
            if aligned {
                rasn::aper::encode(&v)
            } else {
                rasn::uper::encode(&v)
            }
            .map_err(|e| e.to_string())
        }};
    }

    match name {
        // Unconstrained
        "OCTETSTRING-NULL-NULL-FALSE" => enc!(OsNullNullFalse),
        // Semi-constrained
        "OCTETSTRING-0-NULL-FALSE" => enc!(Os0NullFalse),
        "OCTETSTRING-10-NULL-FALSE" => enc!(Os10NullFalse),
        // Constrained, not extensible
        "OCTETSTRING-0-2-FALSE" => enc!(Os0_2False),
        "OCTETSTRING-0-4-FALSE" => enc!(Os0_4False),
        "OCTETSTRING-0-8-FALSE" => enc!(Os0_8False),
        "OCTETSTRING-0-10-FALSE" => enc!(Os0_10False),
        "OCTETSTRING-0-16-FALSE" => enc!(Os0_16False),
        "OCTETSTRING-0-32-FALSE" => enc!(Os0_32False),
        "OCTETSTRING-0-64-FALSE" => enc!(Os0_64False),
        "OCTETSTRING-0-128-FALSE" => enc!(Os0_128False),
        "OCTETSTRING-0-256-FALSE" => enc!(Os0_256False),
        "OCTETSTRING-0-512-FALSE" => enc!(Os0_512False),
        "OCTETSTRING-0-1024-FALSE" => enc!(Os0_1024False),
        "OCTETSTRING-0-2048-FALSE" => enc!(Os0_2048False),
        "OCTETSTRING-0-4096-FALSE" => enc!(Os0_4096False),
        "OCTETSTRING-0-8192-FALSE" => enc!(Os0_8192False),
        "OCTETSTRING-0-16384-FALSE" => enc!(Os0_16384False),
        "OCTETSTRING-0-32768-FALSE" => enc!(Os0_32768False),
        "OCTETSTRING-0-65536-FALSE" => enc!(Os0_65536False),
        "OCTETSTRING-0-131072-FALSE" => enc!(Os0_131072False),
        "OCTETSTRING-0-262144-FALSE" => enc!(Os0_262144False),
        "OCTETSTRING-0-524288-FALSE" => enc!(Os0_524288False),
        "OCTETSTRING-0-1048576-FALSE" => enc!(Os0_1048576False),
        "OCTETSTRING-0-2097152-FALSE" => enc!(Os0_2097152False),
        // Extensible
        "OCTETSTRING-0-0-TRUE" => enc!(Os0_0True),
        "OCTETSTRING-0-1-TRUE" => enc!(Os0_1True),
        "OCTETSTRING-0-2-TRUE" => enc!(Os0_2True),
        "OCTETSTRING-0-4-TRUE" => enc!(Os0_4True),
        "OCTETSTRING-0-8-TRUE" => enc!(Os0_8True),
        "OCTETSTRING-0-16-TRUE" => enc!(Os0_16True),
        "OCTETSTRING-0-32-TRUE" => enc!(Os0_32True),
        "OCTETSTRING-0-64-TRUE" => enc!(Os0_64True),
        "OCTETSTRING-0-128-TRUE" => enc!(Os0_128True),
        "OCTETSTRING-0-256-TRUE" => enc!(Os0_256True),
        "OCTETSTRING-0-512-TRUE" => enc!(Os0_512True),
        "OCTETSTRING-0-1024-TRUE" => enc!(Os0_1024True),
        "OCTETSTRING-0-2048-TRUE" => enc!(Os0_2048True),
        "OCTETSTRING-0-4096-TRUE" => enc!(Os0_4096True),
        "OCTETSTRING-0-8192-TRUE" => enc!(Os0_8192True),
        "OCTETSTRING-0-16384-TRUE" => enc!(Os0_16384True),
        "OCTETSTRING-0-32768-TRUE" => enc!(Os0_32768True),
        "OCTETSTRING-0-65536-TRUE" => enc!(Os0_65536True),
        "OCTETSTRING-0-131072-TRUE" => enc!(Os0_131072True),
        "OCTETSTRING-0-262144-TRUE" => enc!(Os0_262144True),
        "OCTETSTRING-0-524288-TRUE" => enc!(Os0_524288True),
        _ => Err(format!("Unknown type: {}", name)),
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = env::args().collect();
    let (mut name, mut length, mut aligned) = (None::<String>, None::<usize>, false);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-name" | "--name" => {
                i += 1;
                name = Some(args[i].clone());
            }
            "-length" | "--length" => {
                i += 1;
                length = Some(args[i].parse().expect("invalid length"));
            }
            "-aligned" | "--aligned" => {
                aligned = true;
            }
            other => {
                eprintln!("error: unknown argument: {}", other);
                eprintln!("Usage: encode-octetstring -name <TypeName> -length <N> [-aligned]");
                process::exit(1);
            }
        }
        i += 1;
    }

    let name = name.unwrap_or_else(|| {
        eprintln!("error: missing -name");
        process::exit(1);
    });
    let length = length.unwrap_or_else(|| {
        eprintln!("error: missing -length");
        process::exit(1);
    });

    let value = gen_pattern(length);

    match encode_octetstring(&name, value, aligned) {
        Ok(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            println!("{}", hex);
        }
        Err(e) => {
            eprintln!("Encode error: {}", e);
            process::exit(1);
        }
    }
}
