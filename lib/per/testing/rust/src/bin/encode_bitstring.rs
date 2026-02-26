/// Encode a named BIT STRING type using rasn (librasn) with APER or UPER.
///
/// Usage:
///   encode-bitstring -name <TypeName> -length <N> [-aligned]
///
/// Flags:
///   -name <TypeName>  ASN.1 type name (e.g. 'BITSTRING-NULL-NULL-FALSE')
///   -length <N>       bit string length in bits
///   -aligned          use APER (aligned PER); omit for UPER (default)
///
/// Output: hex-encoded PER bytes on stdout
///
/// The type names follow the convention: BITSTRING-<LB>-<UB>-<EXT>
///   LB:  lower bound or NULL (unconstrained)
///   UB:  upper bound or NULL (semi-constrained / unconstrained)
///   EXT: TRUE (extensible) or FALSE (not extensible)
use rasn::prelude::*;
use rasn::types::BitString;
use std::env;
use std::process;

// ---------------------------------------------------------------------------
// Type definitions — one per constraint combination
// ---------------------------------------------------------------------------

// Helper macros to reduce boilerplate.  Declarative macros expand before
// proc-macros, so the string-literal constraint values are visible to rasn's
// derive implementation.

macro_rules! def_bs {
    ($name:ident) => {
        #[derive(AsnType, Encode)]
        #[rasn(delegate)]
        struct $name(BitString);
    };
    ($name:ident, $range:literal) => {
        #[derive(AsnType, Encode)]
        #[rasn(delegate, size($range))]
        struct $name(BitString);
    };
}

macro_rules! def_bs_ext {
    ($name:ident, $range:literal) => {
        #[derive(AsnType, Encode)]
        #[rasn(delegate, size($range, extensible))]
        struct $name(BitString);
    };
}

// Unconstrained
def_bs!(BsNullNullFalse);

// Semi-constrained (lb only, ub = MAX)
def_bs!(Bs0NullFalse, "0..");
def_bs!(Bs10NullFalse, "10..");

// Constrained (lb = 0, various ub), not extensible
def_bs!(Bs0_2False, "0..=2");
def_bs!(Bs0_4False, "0..=4");
def_bs!(Bs0_8False, "0..=8");
def_bs!(Bs0_10False, "0..=10");
def_bs!(Bs0_16False, "0..=16");
def_bs!(Bs0_32False, "0..=32");
def_bs!(Bs0_64False, "0..=64");
def_bs!(Bs0_128False, "0..=128");
def_bs!(Bs0_256False, "0..=256");
def_bs!(Bs0_512False, "0..=512");
def_bs!(Bs0_1024False, "0..=1024");
def_bs!(Bs0_2048False, "0..=2048");
def_bs!(Bs0_4096False, "0..=4096");
def_bs!(Bs0_8192False, "0..=8192");
def_bs!(Bs0_16384False, "0..=16384");
def_bs!(Bs0_32768False, "0..=32768");
def_bs!(Bs0_65536False, "0..=65536");
def_bs!(Bs0_131072False, "0..=131072");
def_bs!(Bs0_262144False, "0..=262144");
def_bs!(Bs0_524288False, "0..=524288");
def_bs!(Bs0_1048576False, "0..=1048576");
def_bs!(Bs0_2097152False, "0..=2097152");

// Constrained, extensible (lb = 0, various ub)
def_bs_ext!(Bs0_0True, "0..=0");
def_bs_ext!(Bs0_1True, "0..=1");
def_bs_ext!(Bs0_2True, "0..=2");
def_bs_ext!(Bs0_4True, "0..=4");
def_bs_ext!(Bs0_8True, "0..=8");
def_bs_ext!(Bs0_16True, "0..=16");
def_bs_ext!(Bs0_32True, "0..=32");
def_bs_ext!(Bs0_64True, "0..=64");
def_bs_ext!(Bs0_128True, "0..=128");
def_bs_ext!(Bs0_256True, "0..=256");
def_bs_ext!(Bs0_512True, "0..=512");
def_bs_ext!(Bs0_1024True, "0..=1024");
def_bs_ext!(Bs0_2048True, "0..=2048");
def_bs_ext!(Bs0_4096True, "0..=4096");
def_bs_ext!(Bs0_8192True, "0..=8192");
def_bs_ext!(Bs0_16384True, "0..=16384");
def_bs_ext!(Bs0_32768True, "0..=32768");
def_bs_ext!(Bs0_65536True, "0..=65536");
def_bs_ext!(Bs0_131072True, "0..=131072");
def_bs_ext!(Bs0_262144True, "0..=262144");
def_bs_ext!(Bs0_524288True, "0..=524288");

// ---------------------------------------------------------------------------
// Bit pattern generator — alternating 01010101… (0x55 per byte)
// ---------------------------------------------------------------------------

fn gen_alt(length: usize) -> BitString {
    let total_bytes = (length + 7) / 8;
    let mut bytes = vec![0x55u8; total_bytes];
    // Clear unused trailing bits in last byte
    let rem = length % 8;
    if rem > 0 {
        bytes[total_bytes - 1] = 0x55 & (0xFFu8 << (8 - rem));
    }
    let mut bs = BitString::from_vec(bytes);
    bs.truncate(length);
    bs
}

// ---------------------------------------------------------------------------
// Encode dispatcher — maps type name string to the appropriate rasn type
// ---------------------------------------------------------------------------

fn encode_bitstring(name: &str, value: BitString, aligned: bool) -> Result<Vec<u8>, String> {
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
        "BITSTRING-NULL-NULL-FALSE" => enc!(BsNullNullFalse),
        // Semi-constrained
        "BITSTRING-0-NULL-FALSE" => enc!(Bs0NullFalse),
        "BITSTRING-10-NULL-FALSE" => enc!(Bs10NullFalse),
        // Constrained, not extensible
        "BITSTRING-0-2-FALSE" => enc!(Bs0_2False),
        "BITSTRING-0-4-FALSE" => enc!(Bs0_4False),
        "BITSTRING-0-8-FALSE" => enc!(Bs0_8False),
        "BITSTRING-0-10-FALSE" => enc!(Bs0_10False),
        "BITSTRING-0-16-FALSE" => enc!(Bs0_16False),
        "BITSTRING-0-32-FALSE" => enc!(Bs0_32False),
        "BITSTRING-0-64-FALSE" => enc!(Bs0_64False),
        "BITSTRING-0-128-FALSE" => enc!(Bs0_128False),
        "BITSTRING-0-256-FALSE" => enc!(Bs0_256False),
        "BITSTRING-0-512-FALSE" => enc!(Bs0_512False),
        "BITSTRING-0-1024-FALSE" => enc!(Bs0_1024False),
        "BITSTRING-0-2048-FALSE" => enc!(Bs0_2048False),
        "BITSTRING-0-4096-FALSE" => enc!(Bs0_4096False),
        "BITSTRING-0-8192-FALSE" => enc!(Bs0_8192False),
        "BITSTRING-0-16384-FALSE" => enc!(Bs0_16384False),
        "BITSTRING-0-32768-FALSE" => enc!(Bs0_32768False),
        "BITSTRING-0-65536-FALSE" => enc!(Bs0_65536False),
        "BITSTRING-0-131072-FALSE" => enc!(Bs0_131072False),
        "BITSTRING-0-262144-FALSE" => enc!(Bs0_262144False),
        "BITSTRING-0-524288-FALSE" => enc!(Bs0_524288False),
        "BITSTRING-0-1048576-FALSE" => enc!(Bs0_1048576False),
        "BITSTRING-0-2097152-FALSE" => enc!(Bs0_2097152False),
        // Extensible
        "BITSTRING-0-0-TRUE" => enc!(Bs0_0True),
        "BITSTRING-0-1-TRUE" => enc!(Bs0_1True),
        "BITSTRING-0-2-TRUE" => enc!(Bs0_2True),
        "BITSTRING-0-4-TRUE" => enc!(Bs0_4True),
        "BITSTRING-0-8-TRUE" => enc!(Bs0_8True),
        "BITSTRING-0-16-TRUE" => enc!(Bs0_16True),
        "BITSTRING-0-32-TRUE" => enc!(Bs0_32True),
        "BITSTRING-0-64-TRUE" => enc!(Bs0_64True),
        "BITSTRING-0-128-TRUE" => enc!(Bs0_128True),
        "BITSTRING-0-256-TRUE" => enc!(Bs0_256True),
        "BITSTRING-0-512-TRUE" => enc!(Bs0_512True),
        "BITSTRING-0-1024-TRUE" => enc!(Bs0_1024True),
        "BITSTRING-0-2048-TRUE" => enc!(Bs0_2048True),
        "BITSTRING-0-4096-TRUE" => enc!(Bs0_4096True),
        "BITSTRING-0-8192-TRUE" => enc!(Bs0_8192True),
        "BITSTRING-0-16384-TRUE" => enc!(Bs0_16384True),
        "BITSTRING-0-32768-TRUE" => enc!(Bs0_32768True),
        "BITSTRING-0-65536-TRUE" => enc!(Bs0_65536True),
        "BITSTRING-0-131072-TRUE" => enc!(Bs0_131072True),
        "BITSTRING-0-262144-TRUE" => enc!(Bs0_262144True),
        "BITSTRING-0-524288-TRUE" => enc!(Bs0_524288True),
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
                eprintln!("Usage: encode-bitstring -name <TypeName> -length <N> [-aligned]");
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

    let value = gen_alt(length);

    match encode_bitstring(&name, value, aligned) {
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
