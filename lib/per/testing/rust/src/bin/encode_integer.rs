/// Encode a named INTEGER type using rasn (librasn) with APER or UPER.
///
/// Usage:
///   encode-integer -name <TypeName> -value <N> [-aligned]
///
/// Flags:
///   -name <TypeName>  ASN.1 type name (e.g. 'INTEGER-0-100-FALSE')
///   -value <N>        integer value to encode
///   -aligned          use APER (aligned PER); omit for UPER (default)
///
/// Output: hex-encoded PER bytes on stdout
///
/// The type names follow the convention: INTEGER-<LB>-<UB>-<EXT>
///   LB:  lower bound, NULL (unconstrained), or N-prefixed for negative (e.g. N100 = -100)
///   UB:  upper bound, NULL (semi-constrained / unconstrained), or N-prefixed for negative
///   EXT: TRUE (extensible) or FALSE (not extensible)
///
/// # rasn limitations (rasn 0.28.x)
///
/// The following categories produce INCORRECT or UNSUPPORTED encodings:
///
/// 1. **Unconstrained INTEGER (NULL..NULL, FALSE)**
///    BROKEN: rasn encodes as a fixed 8-byte i64 (e.g. value 0 → "8000000000000000")
///    instead of PER length-determinant + 2's complement bytes (Erlang: 0 → "0100").
///
/// 2. **Semi-constrained INTEGER (lb..MAX, FALSE)**
///    BROKEN: rasn encodes as a fixed 8-byte offset (e.g. 0..MAX value 0 → "0000000000000000")
///    instead of PER length-determinant + offset bytes (Erlang: 0 → "0100").
///
/// 3. **Semi-constrained extensible INTEGER (lb..MAX, TRUE)**
///    BROKEN (in-range): same fixed 8-byte encoding as non-extensible semi-constrained.
///    FAILS (out-of-range): rasn rejects values below lb with constraint error,
///    e.g. INTEGER (0..MAX, ...) value -100 → error instead of extension encoding.
///
/// 4. **Extensible constrained out-of-range values (lb..ub, TRUE)**
///    FAILS: rasn rejects any value outside [lb..ub] even when extensible is declared.
///    Per X.691, extensible types MUST encode out-of-range values using the extension
///    mechanism (extension bit = 1 + unconstrained encoding). rasn returns:
///    "Value constraint not satisfied: expected: lb..ub; actual: N"
///    This affects ALL extensible types when the value falls outside the root range.
///
/// Only constrained types (both extensible and non-extensible) with IN-RANGE values
/// produce correct PER encodings.
use rasn::prelude::*;
use std::env;
use std::process;

// ---------------------------------------------------------------------------
// Type definitions — one per constraint combination
// ---------------------------------------------------------------------------

// Helper macros to reduce boilerplate.

macro_rules! def_int {
    ($name:ident) => {
        #[derive(AsnType, Encode)]
        #[rasn(delegate)]
        struct $name(i64);
    };
    ($name:ident, $range:literal) => {
        #[derive(AsnType, Encode)]
        #[rasn(delegate, value($range))]
        struct $name(i64);
    };
}

macro_rules! def_int_ext {
    ($name:ident, $range:literal) => {
        #[derive(AsnType, Encode)]
        #[rasn(delegate, value($range, extensible))]
        struct $name(i64);
    };
}

// ===== Unconstrained =====
// BROKEN: rasn encodes as fixed 8-byte i64 instead of length-determinant encoding
def_int!(IntNullNullFalse);

// ===== Semi-constrained (lb..MAX), not extensible =====
// BROKEN: rasn encodes as fixed 8-byte offset instead of length-determinant encoding
def_int!(Int0NullFalse, "0..");
def_int!(Int10NullFalse, "10..");
def_int!(Int20NullFalse, "20..");
def_int!(Int100NullFalse, "100..");
def_int!(IntN10NullFalse, "-10..");
def_int!(IntN100NullFalse, "-100..");
def_int!(IntN200NullFalse, "-200..");

// ===== Semi-constrained (lb..MAX), extensible =====
// BROKEN: in-range uses same broken fixed 8-byte encoding as non-extensible
// FAILS: out-of-range values rejected with constraint error
def_int_ext!(Int0NullTrue, "0..");
def_int_ext!(Int10NullTrue, "10..");
def_int_ext!(Int20NullTrue, "20..");
def_int_ext!(IntN100NullTrue, "-100..");

// ===== Constrained (0..X), not extensible =====
def_int!(Int0_1False, "0..=1");
def_int!(Int0_2False, "0..=2");
def_int!(Int0_4False, "0..=4");
def_int!(Int0_8False, "0..=8");
def_int!(Int0_16False, "0..=16");
def_int!(Int0_32False, "0..=32");
def_int!(Int0_64False, "0..=64");
def_int!(Int0_99False, "0..=99");
def_int!(Int0_100False, "0..=100");
def_int!(Int0_127False, "0..=127");
def_int!(Int0_128False, "0..=128");
def_int!(Int0_200False, "0..=200");
def_int!(Int0_253False, "0..=253");
def_int!(Int0_254False, "0..=254");
def_int!(Int0_255False, "0..=255");
def_int!(Int0_256False, "0..=256");
def_int!(Int0_257False, "0..=257");
def_int!(Int0_511False, "0..=511");
def_int!(Int0_512False, "0..=512");
def_int!(Int0_1000False, "0..=1000");
def_int!(Int0_1024False, "0..=1024");
def_int!(Int0_2047False, "0..=2047");
def_int!(Int0_2048False, "0..=2048");
def_int!(Int0_4096False, "0..=4096");
def_int!(Int0_8192False, "0..=8192");
def_int!(Int0_10000False, "0..=10000");
def_int!(Int0_16384False, "0..=16384");
def_int!(Int0_32768False, "0..=32768");
def_int!(Int0_65534False, "0..=65534");
def_int!(Int0_65535False, "0..=65535");
def_int!(Int0_65536False, "0..=65536");
def_int!(Int0_65537False, "0..=65537");
def_int!(Int0_100000False, "0..=100000");
def_int!(Int0_131072False, "0..=131072");
def_int!(Int0_262144False, "0..=262144");
def_int!(Int0_524288False, "0..=524288");
def_int!(Int0_1000000False, "0..=1000000");
def_int!(Int0_1048576False, "0..=1048576");
def_int!(Int0_2097152False, "0..=2097152");
def_int!(Int0_4194304False, "0..=4194304");
def_int!(Int0_8388608False, "0..=8388608");
def_int!(Int0_16777216False, "0..=16777216");
def_int!(Int0_33554432False, "0..=33554432");
def_int!(Int0_67108864False, "0..=67108864");
def_int!(Int0_134217728False, "0..=134217728");
def_int!(Int0_268435456False, "0..=268435456");

// ===== Other non-negative ranges, not extensible =====
def_int!(Int1_1False, "1..=1");
def_int!(Int1_3False, "1..=3");
def_int!(Int10_150False, "10..=150");
def_int!(Int20_40False, "20..=40");
def_int!(Int50_50False, "50..=50");
def_int!(Int50_100False, "50..=100");
def_int!(Int100_200False, "100..=200");

// ===== Negative ranges, not extensible =====
def_int!(IntN10_10False, "-10..=10");
def_int!(IntN50_50False, "-50..=50");
def_int!(IntN100_N10False, "-100..=-10");
def_int!(IntN100_100False, "-100..=100");
def_int!(IntN200_N10False, "-200..=-10");

// ===== Constrained (0..X), extensible =====
// NOTE: in-range values encode correctly; out-of-range values FAIL with constraint error
def_int_ext!(Int0_1True, "0..=1");
def_int_ext!(Int0_2True, "0..=2");
def_int_ext!(Int0_4True, "0..=4");
def_int_ext!(Int0_8True, "0..=8");
def_int_ext!(Int0_16True, "0..=16");
def_int_ext!(Int0_32True, "0..=32");
def_int_ext!(Int0_64True, "0..=64");
def_int_ext!(Int0_99True, "0..=99");
def_int_ext!(Int0_100True, "0..=100");
def_int_ext!(Int0_128True, "0..=128");
def_int_ext!(Int0_200True, "0..=200");
def_int_ext!(Int0_256True, "0..=256");
def_int_ext!(Int0_257True, "0..=257");
def_int_ext!(Int0_512True, "0..=512");
def_int_ext!(Int0_1000True, "0..=1000");
def_int_ext!(Int0_1024True, "0..=1024");
def_int_ext!(Int0_2048True, "0..=2048");
def_int_ext!(Int0_4096True, "0..=4096");
def_int_ext!(Int0_8192True, "0..=8192");
def_int_ext!(Int0_10000True, "0..=10000");
def_int_ext!(Int0_16384True, "0..=16384");
def_int_ext!(Int0_32768True, "0..=32768");
def_int_ext!(Int0_65535True, "0..=65535");
def_int_ext!(Int0_65536True, "0..=65536");
def_int_ext!(Int0_100000True, "0..=100000");
def_int_ext!(Int0_131072True, "0..=131072");
def_int_ext!(Int0_262144True, "0..=262144");
def_int_ext!(Int0_524288True, "0..=524288");
def_int_ext!(Int0_1000000True, "0..=1000000");
def_int_ext!(Int0_1048576True, "0..=1048576");
def_int_ext!(Int0_2097152True, "0..=2097152");
def_int_ext!(Int0_4194304True, "0..=4194304");
def_int_ext!(Int0_8388608True, "0..=8388608");
def_int_ext!(Int0_16777216True, "0..=16777216");
def_int_ext!(Int0_33554432True, "0..=33554432");
def_int_ext!(Int0_67108864True, "0..=67108864");
def_int_ext!(Int0_134217728True, "0..=134217728");
def_int_ext!(Int0_268435456True, "0..=268435456");

// ===== Other non-negative ranges, extensible =====
// NOTE: in-range values encode correctly; out-of-range values FAIL with constraint error
def_int_ext!(Int1_1True, "1..=1");
def_int_ext!(Int1_3True, "1..=3");
def_int_ext!(Int10_150True, "10..=150");
def_int_ext!(Int20_40True, "20..=40");
def_int_ext!(Int50_50True, "50..=50");
def_int_ext!(Int50_100True, "50..=100");
def_int_ext!(Int100_100True, "100..=100");
def_int_ext!(Int100_200True, "100..=200");
def_int_ext!(Int1000_1000True, "1000..=1000");

// ===== Negative ranges, extensible =====
// NOTE: in-range values encode correctly; out-of-range values FAIL with constraint error
def_int_ext!(IntN10_10True, "-10..=10");
def_int_ext!(IntN50_50True, "-50..=50");
def_int_ext!(IntN100_N10True, "-100..=-10");
def_int_ext!(IntN100_100True, "-100..=100");
def_int_ext!(IntN500_500True, "-500..=500");

// ---------------------------------------------------------------------------
// Encode dispatcher — maps type name string to the appropriate rasn type
// ---------------------------------------------------------------------------

fn encode_integer(name: &str, value: i64, aligned: bool) -> Result<Vec<u8>, String> {
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
        // Unconstrained (BROKEN: fixed 8-byte i64 encoding)
        "INTEGER-NULL-NULL-FALSE" => enc!(IntNullNullFalse),

        // Semi-constrained, not extensible (BROKEN: fixed 8-byte offset encoding)
        "INTEGER-0-NULL-FALSE" => enc!(Int0NullFalse),
        "INTEGER-10-NULL-FALSE" => enc!(Int10NullFalse),
        "INTEGER-20-NULL-FALSE" => enc!(Int20NullFalse),
        "INTEGER-100-NULL-FALSE" => enc!(Int100NullFalse),
        "INTEGER-N10-NULL-FALSE" => enc!(IntN10NullFalse),
        "INTEGER-N100-NULL-FALSE" => enc!(IntN100NullFalse),
        "INTEGER-N200-NULL-FALSE" => enc!(IntN200NullFalse),

        // Semi-constrained, extensible (BROKEN in-range; FAILS out-of-range)
        "INTEGER-0-NULL-TRUE" => enc!(Int0NullTrue),
        "INTEGER-10-NULL-TRUE" => enc!(Int10NullTrue),
        "INTEGER-20-NULL-TRUE" => enc!(Int20NullTrue),
        "INTEGER-N100-NULL-TRUE" => enc!(IntN100NullTrue),

        // Constrained (0..X), not extensible
        "INTEGER-0-1-FALSE" => enc!(Int0_1False),
        "INTEGER-0-2-FALSE" => enc!(Int0_2False),
        "INTEGER-0-4-FALSE" => enc!(Int0_4False),
        "INTEGER-0-8-FALSE" => enc!(Int0_8False),
        "INTEGER-0-16-FALSE" => enc!(Int0_16False),
        "INTEGER-0-32-FALSE" => enc!(Int0_32False),
        "INTEGER-0-64-FALSE" => enc!(Int0_64False),
        "INTEGER-0-99-FALSE" => enc!(Int0_99False),
        "INTEGER-0-100-FALSE" => enc!(Int0_100False),
        "INTEGER-0-127-FALSE" => enc!(Int0_127False),
        "INTEGER-0-128-FALSE" => enc!(Int0_128False),
        "INTEGER-0-200-FALSE" => enc!(Int0_200False),
        "INTEGER-0-253-FALSE" => enc!(Int0_253False),
        "INTEGER-0-254-FALSE" => enc!(Int0_254False),
        "INTEGER-0-255-FALSE" => enc!(Int0_255False),
        "INTEGER-0-256-FALSE" => enc!(Int0_256False),
        "INTEGER-0-257-FALSE" => enc!(Int0_257False),
        "INTEGER-0-511-FALSE" => enc!(Int0_511False),
        "INTEGER-0-512-FALSE" => enc!(Int0_512False),
        "INTEGER-0-1000-FALSE" => enc!(Int0_1000False),
        "INTEGER-0-1024-FALSE" => enc!(Int0_1024False),
        "INTEGER-0-2047-FALSE" => enc!(Int0_2047False),
        "INTEGER-0-2048-FALSE" => enc!(Int0_2048False),
        "INTEGER-0-4096-FALSE" => enc!(Int0_4096False),
        "INTEGER-0-8192-FALSE" => enc!(Int0_8192False),
        "INTEGER-0-10000-FALSE" => enc!(Int0_10000False),
        "INTEGER-0-16384-FALSE" => enc!(Int0_16384False),
        "INTEGER-0-32768-FALSE" => enc!(Int0_32768False),
        "INTEGER-0-65534-FALSE" => enc!(Int0_65534False),
        "INTEGER-0-65535-FALSE" => enc!(Int0_65535False),
        "INTEGER-0-65536-FALSE" => enc!(Int0_65536False),
        "INTEGER-0-65537-FALSE" => enc!(Int0_65537False),
        "INTEGER-0-100000-FALSE" => enc!(Int0_100000False),
        "INTEGER-0-131072-FALSE" => enc!(Int0_131072False),
        "INTEGER-0-262144-FALSE" => enc!(Int0_262144False),
        "INTEGER-0-524288-FALSE" => enc!(Int0_524288False),
        "INTEGER-0-1000000-FALSE" => enc!(Int0_1000000False),
        "INTEGER-0-1048576-FALSE" => enc!(Int0_1048576False),
        "INTEGER-0-2097152-FALSE" => enc!(Int0_2097152False),
        "INTEGER-0-4194304-FALSE" => enc!(Int0_4194304False),
        "INTEGER-0-8388608-FALSE" => enc!(Int0_8388608False),
        "INTEGER-0-16777216-FALSE" => enc!(Int0_16777216False),
        "INTEGER-0-33554432-FALSE" => enc!(Int0_33554432False),
        "INTEGER-0-67108864-FALSE" => enc!(Int0_67108864False),
        "INTEGER-0-134217728-FALSE" => enc!(Int0_134217728False),
        "INTEGER-0-268435456-FALSE" => enc!(Int0_268435456False),

        // Other non-negative ranges, not extensible
        "INTEGER-1-1-FALSE" => enc!(Int1_1False),
        "INTEGER-1-3-FALSE" => enc!(Int1_3False),
        "INTEGER-10-150-FALSE" => enc!(Int10_150False),
        "INTEGER-20-40-FALSE" => enc!(Int20_40False),
        "INTEGER-50-50-FALSE" => enc!(Int50_50False),
        "INTEGER-50-100-FALSE" => enc!(Int50_100False),
        "INTEGER-100-200-FALSE" => enc!(Int100_200False),

        // Negative ranges, not extensible
        "INTEGER-N10-10-FALSE" => enc!(IntN10_10False),
        "INTEGER-N50-50-FALSE" => enc!(IntN50_50False),
        "INTEGER-N100-N10-FALSE" => enc!(IntN100_N10False),
        "INTEGER-N100-100-FALSE" => enc!(IntN100_100False),
        "INTEGER-N200-N10-FALSE" => enc!(IntN200_N10False),

        // Constrained (0..X), extensible (in-range OK; out-of-range FAILS)
        "INTEGER-0-1-TRUE" => enc!(Int0_1True),
        "INTEGER-0-2-TRUE" => enc!(Int0_2True),
        "INTEGER-0-4-TRUE" => enc!(Int0_4True),
        "INTEGER-0-8-TRUE" => enc!(Int0_8True),
        "INTEGER-0-16-TRUE" => enc!(Int0_16True),
        "INTEGER-0-32-TRUE" => enc!(Int0_32True),
        "INTEGER-0-64-TRUE" => enc!(Int0_64True),
        "INTEGER-0-99-TRUE" => enc!(Int0_99True),
        "INTEGER-0-100-TRUE" => enc!(Int0_100True),
        "INTEGER-0-128-TRUE" => enc!(Int0_128True),
        "INTEGER-0-200-TRUE" => enc!(Int0_200True),
        "INTEGER-0-256-TRUE" => enc!(Int0_256True),
        "INTEGER-0-257-TRUE" => enc!(Int0_257True),
        "INTEGER-0-512-TRUE" => enc!(Int0_512True),
        "INTEGER-0-1000-TRUE" => enc!(Int0_1000True),
        "INTEGER-0-1024-TRUE" => enc!(Int0_1024True),
        "INTEGER-0-2048-TRUE" => enc!(Int0_2048True),
        "INTEGER-0-4096-TRUE" => enc!(Int0_4096True),
        "INTEGER-0-8192-TRUE" => enc!(Int0_8192True),
        "INTEGER-0-10000-TRUE" => enc!(Int0_10000True),
        "INTEGER-0-16384-TRUE" => enc!(Int0_16384True),
        "INTEGER-0-32768-TRUE" => enc!(Int0_32768True),
        "INTEGER-0-65535-TRUE" => enc!(Int0_65535True),
        "INTEGER-0-65536-TRUE" => enc!(Int0_65536True),
        "INTEGER-0-100000-TRUE" => enc!(Int0_100000True),
        "INTEGER-0-131072-TRUE" => enc!(Int0_131072True),
        "INTEGER-0-262144-TRUE" => enc!(Int0_262144True),
        "INTEGER-0-524288-TRUE" => enc!(Int0_524288True),
        "INTEGER-0-1000000-TRUE" => enc!(Int0_1000000True),
        "INTEGER-0-1048576-TRUE" => enc!(Int0_1048576True),
        "INTEGER-0-2097152-TRUE" => enc!(Int0_2097152True),
        "INTEGER-0-4194304-TRUE" => enc!(Int0_4194304True),
        "INTEGER-0-8388608-TRUE" => enc!(Int0_8388608True),
        "INTEGER-0-16777216-TRUE" => enc!(Int0_16777216True),
        "INTEGER-0-33554432-TRUE" => enc!(Int0_33554432True),
        "INTEGER-0-67108864-TRUE" => enc!(Int0_67108864True),
        "INTEGER-0-134217728-TRUE" => enc!(Int0_134217728True),
        "INTEGER-0-268435456-TRUE" => enc!(Int0_268435456True),

        // Other non-negative ranges, extensible (in-range OK; out-of-range FAILS)
        "INTEGER-1-1-TRUE" => enc!(Int1_1True),
        "INTEGER-1-3-TRUE" => enc!(Int1_3True),
        "INTEGER-10-150-TRUE" => enc!(Int10_150True),
        "INTEGER-20-40-TRUE" => enc!(Int20_40True),
        "INTEGER-50-50-TRUE" => enc!(Int50_50True),
        "INTEGER-50-100-TRUE" => enc!(Int50_100True),
        "INTEGER-100-100-TRUE" => enc!(Int100_100True),
        "INTEGER-100-200-TRUE" => enc!(Int100_200True),
        "INTEGER-1000-1000-TRUE" => enc!(Int1000_1000True),

        // Negative ranges, extensible (in-range OK; out-of-range FAILS)
        "INTEGER-N10-10-TRUE" => enc!(IntN10_10True),
        "INTEGER-N50-50-TRUE" => enc!(IntN50_50True),
        "INTEGER-N100-N10-TRUE" => enc!(IntN100_N10True),
        "INTEGER-N100-100-TRUE" => enc!(IntN100_100True),
        "INTEGER-N500-500-TRUE" => enc!(IntN500_500True),

        _ => Err(format!("Unknown type: {}", name)),
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = env::args().collect();
    let (mut name, mut value, mut aligned) = (None::<String>, None::<i64>, false);

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-name" | "--name" => {
                i += 1;
                name = Some(args[i].clone());
            }
            "-value" | "--value" => {
                i += 1;
                value = Some(args[i].parse().expect("invalid integer value"));
            }
            "-aligned" | "--aligned" => {
                aligned = true;
            }
            other => {
                eprintln!("error: unknown argument: {}", other);
                eprintln!("Usage: encode-integer -name <TypeName> -value <N> [-aligned]");
                process::exit(1);
            }
        }
        i += 1;
    }

    let name = name.unwrap_or_else(|| {
        eprintln!("error: missing -name");
        process::exit(1);
    });
    let value = value.unwrap_or_else(|| {
        eprintln!("error: missing -value");
        process::exit(1);
    });

    match encode_integer(&name, value, aligned) {
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
