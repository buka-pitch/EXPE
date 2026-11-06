/// Shannon entropy in bits per byte, range 0..=8.
#[must_use]
// Byte and count totals are bounded by the address space; f64 is intentionally
// used only for the probability ratio.
#[allow(clippy::cast_precision_loss)]
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for &byte in data {
        counts[usize::from(byte)] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

/// Entropy over at most `max_bytes`, sampled from the start. Keeps whole-file
/// scoring cheap for multi-hundred-megabyte inputs.
#[must_use]
pub fn entropy_sampled(data: &[u8], max_bytes: u64) -> f64 {
    let limit = usize::try_from(max_bytes)
        .unwrap_or(usize::MAX)
        .min(data.len());
    entropy(&data[..limit])
}

#[must_use]
pub fn entropy_of_range(data: &[u8], offset: u64, size: u64) -> f64 {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let end = start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
    data.get(start..end).map_or(0.0, entropy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        assert!((entropy(b"") - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn uniform_single_byte_is_zero() {
        assert!((entropy(&[0x41; 4096]) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn uniform_256_values_is_eight() {
        let data: Vec<u8> = (0..=255).cycle().take(65536).collect();
        assert!((entropy(&data) - 8.0).abs() < 1e-9);
    }

    #[test]
    fn two_symbols_is_one_bit() {
        let data: Vec<u8> = [0_u8, 1].repeat(4096);
        assert!((entropy(&data) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn range_is_bounded() {
        let data = b"abcabcabc";
        assert!((entropy_of_range(data, 0, 3) - entropy(b"abc")).abs() < f64::EPSILON);
        assert!((entropy_of_range(data, 900, 3) - 0.0).abs() < f64::EPSILON);
    }
}
