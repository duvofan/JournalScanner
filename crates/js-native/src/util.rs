#[inline]
pub fn rd16(p: &[u8], o: usize) -> u16 {
    match p.get(o..o + 2) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}
#[inline]
pub fn rd32(p: &[u8], o: usize) -> u32 {
    match p.get(o..o + 4) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}
#[inline]
pub fn rd64(p: &[u8], o: usize) -> u64 {
    rd32(p, o) as u64 | ((rd32(p, o + 4) as u64) << 32)
}
#[inline]
pub fn rd16be(p: &[u8], o: usize) -> u16 {
    match p.get(o..o + 2) {
        Some(b) => u16::from_be_bytes([b[0], b[1]]),
        None => 0,
    }
}
#[inline]
pub fn rd32be(p: &[u8], o: usize) -> u32 {
    match p.get(o..o + 4) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}

#[inline]
pub fn is_al(c: u8) -> bool {
    c.is_ascii_alphabetic()
}
#[inline]
pub fn is_dig(c: u8) -> bool {
    c.is_ascii_digit()
}
#[inline]
pub fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}
#[inline]
pub fn is_lower(c: u8) -> bool {
    c.is_ascii_lowercase()
}
#[inline]
pub fn is_upper(c: u8) -> bool {
    c.is_ascii_uppercase()
}
#[inline]
pub fn is_print_a(c: u8) -> bool {
    (0x20..=0x7E).contains(&c) || c == b'\t'
}
#[inline]
pub fn low_c(c: u8) -> u8 {
    c.to_ascii_lowercase()
}

pub fn lower_str(s: &str) -> String {
    s.chars().map(|c| c.to_ascii_lowercase()).collect()
}

pub fn latin1(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

pub fn hex_bytes(p: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(p.len() * 2);
    for &b in p {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

pub fn fmt_size(n: u64) -> String {
    if n < 1024 {
        format!("{} B", n)
    } else if n < 1024 * 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1} MB", n as f64 / 1048576.0)
    } else {
        format!("{:.2} GB", n as f64 / 1073741824.0)
    }
}

pub fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", String::from_utf8_lossy(&s.as_bytes()[..n]))
    }
}

pub fn printable(s: &str) -> String {
    s.bytes()
        .map(|c| if !(0x20..=0x7E).contains(&c) { '.' } else { c as char })
        .collect()
}

pub fn fmt_time(t: u32) -> String {
    if t == 0 {
        return "-".to_string();
    }
    let secs = t as i64;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn hex(v: u64) -> String {
    format!("0x{:X}", v)
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

fn sha_block(h: &mut [u32; 8], p: &[u8]) {
    let mut w = [0u32; 64];
    for (i, wi) in w.iter_mut().enumerate().take(16) {
        *wi = rd32be(p, i * 4);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let mj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(mj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(y);
    }
}

pub fn sha256_hex(d: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let n = d.len();
    let mut i = 0;
    while i + 64 <= n {
        sha_block(&mut h, &d[i..i + 64]);
        i += 64;
    }
    let mut tail = [0u8; 128];
    let rem = n - i;
    tail[..rem].copy_from_slice(&d[i..]);
    tail[rem] = 0x80;
    let tl = if rem + 9 <= 64 { 64 } else { 128 };
    let bits = (n as u64).wrapping_mul(8);
    for k in 0..8 {
        tail[tl - 1 - k] = (bits >> (8 * k)) as u8;
    }
    sha_block(&mut h, &tail[..64]);
    if tl == 128 {
        sha_block(&mut h, &tail[64..128]);
    }
    let mut out = [0u8; 32];
    for k in 0..8 {
        out[k * 4..k * 4 + 4].copy_from_slice(&h[k].to_be_bytes());
    }
    hex_bytes(&out)
}

pub fn katla(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ç' => 'c',
            'ğ' => 'g',
            'ı' => 'i',
            'ö' => 'o',
            'ş' => 's',
            'ü' => 'u',
            'Ç' => 'C',
            'Ğ' => 'G',
            'İ' => 'I',
            'Ö' => 'O',
            'Ş' => 'S',
            'Ü' => 'U',
            _ => c,
        })
        .collect()
}

pub fn entropy_of(p: &[u8]) -> f64 {
    if p.is_empty() {
        return 0.0;
    }
    let mut cnt = [0u64; 256];
    for &b in p {
        cnt[b as usize] += 1;
    }
    let n = p.len() as f64;
    let mut e = 0.0;
    for &c in cnt.iter() {
        if c != 0 {
            let q = c as f64 / n;
            e -= q * q.log2();
        }
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn time_fmt() {
        assert_eq!(fmt_time(0), "-");
        assert_eq!(fmt_time(86400), "1970-01-02 00:00:00 UTC");
        assert_eq!(fmt_time(1700000000), "2023-11-14 22:13:20 UTC");
    }
    #[test]
    fn sizes() {
        assert_eq!(fmt_size(10), "10 B");
        assert_eq!(fmt_size(2048), "2.0 KB");
    }
}
