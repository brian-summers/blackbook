//! Presentation-layer encodings — fun, human-friendly ways to render binary
//! identifiers and fingerprints. None of these are cryptographic; they're for
//! display and at-a-glance human verification only.
//!
//! - [`randomart`] — the OpenSSH "drunken bishop" visual fingerprint. The eye
//!   spots "that's not the key I expected" instantly, far better than comparing
//!   hex by hand.
//! - [`braille`] — one Unicode braille cell per byte (U+2800+byte): the most
//!   compact rendering possible, one glyph per byte.
//! - [`ucas`] — one Unified Canadian Aboriginal Syllabic per byte
//!   (U+1401+byte): also one glyph per byte, with a distinctive look.

/// One braille pattern glyph per byte (`U+2800`–`U+28FF`). 32 bytes → 32 chars.
pub fn braille(data: &[u8]) -> String {
    data.iter().map(|&b| char::from_u32(0x2800 + b as u32).unwrap()).collect()
}

/// One Unified Canadian Aboriginal Syllabic per byte (`U+1401`–`U+1500`, all
/// assigned). 32 bytes → 32 chars.
pub fn ucas(data: &[u8]) -> String {
    data.iter().map(|&b| char::from_u32(0x1401 + b as u32).unwrap()).collect()
}

/// OpenSSH-style "randomart": a 17×9 grid produced by a "drunken bishop" walk
/// driven by the bytes. Each byte contributes four diagonal steps (2 bits
/// each); cells accumulate visits, rendered with a coin gradient. The start is
/// `S`, the end `E`. `title` is centered in the top border (truncated to fit).
pub fn randomart(data: &[u8], title: &str) -> String {
    const W: usize = 17;
    const H: usize = 9;
    // Visit-count → glyph. Index saturates at the last symbol.
    const COINS: &[u8] = b" .o+=*BOX@%&#/^";

    let mut field = vec![[0u8; W]; H];
    let (mut x, mut y) = (W / 2, H / 2);
    let (sx, sy) = (x, y);
    for &byte in data {
        let mut b = byte;
        for _ in 0..4 {
            let d = b & 0b11;
            if d & 0b01 == 0 { x = x.saturating_sub(1); } else if x < W - 1 { x += 1; }
            if d & 0b10 == 0 { y = y.saturating_sub(1); } else if y < H - 1 { y += 1; }
            let c = &mut field[y][x];
            if (*c as usize) < COINS.len() - 1 { *c += 1; }
            b >>= 2;
        }
    }

    let mut out = String::new();
    out.push('+');
    out.push_str(&center_in(title, W));
    out.push_str("+\n");
    for (j, row) in field.iter().enumerate() {
        out.push('|');
        for (i, &v) in row.iter().enumerate() {
            let ch = if i == sx && j == sy { 'S' }
                     else if i == x && j == y { 'E' }
                     else { COINS[v as usize] as char };
            out.push(ch);
        }
        out.push_str("|\n");
    }
    out.push('+');
    out.push_str(&"-".repeat(W));
    out.push('+');
    out
}

/// Center `title` (wrapped in `[ ]` if non-empty) within `width` dashes.
fn center_in(title: &str, width: usize) -> String {
    let label = if title.is_empty() { String::new() } else {
        let t: String = title.chars().take(width.saturating_sub(2)).collect();
        format!("[{t}]")
    };
    let pad = width.saturating_sub(label.chars().count());
    let left = pad / 2;
    let right = pad - left;
    format!("{}{}{}", "-".repeat(left), label, "-".repeat(right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn braille_one_glyph_per_byte() {
        assert_eq!(braille(&[0x00, 0xff]), "\u{2800}\u{28ff}");
        assert_eq!(braille(&[1, 2, 3]).chars().count(), 3);
    }

    #[test]
    fn ucas_one_glyph_per_byte_no_tofu() {
        // Every byte maps into the assigned U+1401..=U+1500 range.
        let s = ucas(&(0u8..=255).collect::<Vec<_>>());
        assert_eq!(s.chars().count(), 256);
        assert!(s.chars().all(|c| ('\u{1401}'..='\u{1500}').contains(&c)));
    }

    #[test]
    fn randomart_shape_and_determinism() {
        let a = randomart(&[0x8b, 0xcd, 0x6d, 0x11, 0xb3, 0xb6, 0xa8, 0x6e], "test");
        let b = randomart(&[0x8b, 0xcd, 0x6d, 0x11, 0xb3, 0xb6, 0xa8, 0x6e], "test");
        assert_eq!(a, b, "same input must produce the same art");
        let lines: Vec<&str> = a.lines().collect();
        assert_eq!(lines.len(), 11, "1 top border + 9 rows + 1 bottom border");
        assert!(lines[0].starts_with('+') && lines[0].contains("[test]"));
        assert!(lines[1..10].iter().all(|l| l.chars().count() == 19)); // | + 17 + |
        assert!(a.contains('S') && a.contains('E'));
    }

    #[test]
    fn randomart_differs_on_different_input() {
        let a = randomart(&[0x00; 8], "");
        let b = randomart(&[0xff; 8], "");
        assert_ne!(a, b);
    }
}
