use crate::util::*;

#[derive(Debug, Clone, Default)]
pub struct ClassInfo {
    pub name: String,
    pub super_name: String,
    pub ifaces: Vec<String>,
    pub methods: Vec<String>,
    pub fields: Vec<String>,
    pub strs: Vec<String>,
    pub refs: Vec<String>,
    pub natives: i32,
    pub major: u16,
    pub length: usize,
}

pub fn sanitize_j(s: &[u8], max_len: usize) -> String {
    let mut o = String::new();
    for &c in s {
        if o.len() >= max_len {
            break;
        }
        o.push(if (0x20..=0x7E).contains(&c) { c as char } else { '?' });
    }
    o
}

#[derive(Clone, Copy, Default)]
struct Cp {
    tag: u8,
    a: u16,
    #[allow(dead_code)]
    b: u16,
    off: u32,
    len: u32,
}

fn cp_utf<'a>(p: &'a [u8], cp: &[Cp], idx: u32) -> &'a [u8] {
    if idx == 0 || idx as usize >= cp.len() || cp[idx as usize].tag != 1 {
        return &[];
    }
    let c = &cp[idx as usize];
    p.get(c.off as usize..c.off as usize + c.len as usize).unwrap_or(&[])
}
fn cp_class<'a>(p: &'a [u8], cp: &[Cp], idx: u32) -> &'a [u8] {
    if idx == 0 || idx as usize >= cp.len() || cp[idx as usize].tag != 7 {
        return &[];
    }
    cp_utf(p, cp, cp[idx as usize].a as u32)
}

pub fn parse_class(p: &[u8]) -> Option<ClassInfo> {
    let n = p.len();
    let mut ci = ClassInfo::default();
    if n < 32 || rd32be(p, 0) != 0xCAFEBABE {
        return None;
    }
    ci.major = rd16be(p, 6);
    if ci.major < 45 || ci.major > 80 {
        return None;
    }
    let cp_count = rd16be(p, 8) as usize;
    if cp_count < 2 {
        return None;
    }
    let mut cp = vec![Cp::default(); cp_count];
    let mut pos = 10usize;
    let mut i = 1usize;
    while i < cp_count {
        if pos + 1 > n {
            return None;
        }
        let tag = p[pos];
        pos += 1;
        cp[i].tag = tag;
        match tag {
            1 => {
                if pos + 2 > n {
                    return None;
                }
                let len = rd16be(p, pos) as usize;
                pos += 2;
                if pos + len > n {
                    return None;
                }
                cp[i].off = pos as u32;
                cp[i].len = len as u32;
                pos += len;
            }
            3 | 4 => {
                if pos + 4 > n {
                    return None;
                }
                pos += 4;
            }
            5 | 6 => {
                if pos + 8 > n {
                    return None;
                }
                pos += 8;
                i += 1;
            }
            7 | 8 | 16 | 19 | 20 => {
                if pos + 2 > n {
                    return None;
                }
                cp[i].a = rd16be(p, pos);
                pos += 2;
            }
            9 | 10 | 11 | 12 | 17 | 18 => {
                if pos + 4 > n {
                    return None;
                }
                cp[i].a = rd16be(p, pos);
                cp[i].b = rd16be(p, pos + 2);
                pos += 4;
            }
            15 => {
                if pos + 3 > n {
                    return None;
                }
                cp[i].a = p[pos] as u16;
                cp[i].b = rd16be(p, pos + 1);
                pos += 3;
            }
            _ => return None,
        }
        i += 1;
    }
    if pos + 10 > n {
        return None;
    }
    pos += 2;
    let this_c = rd16be(p, pos) as u32;
    pos += 2;
    let super_c = rd16be(p, pos) as u32;
    pos += 2;
    let n_if = rd16be(p, pos);
    pos += 2;
    ci.name = sanitize_j(cp_class(p, &cp, this_c), 160);
    ci.super_name = sanitize_j(cp_class(p, &cp, super_c), 160);
    if ci.name.is_empty() {
        return None;
    }
    for _ in 0..n_if {
        if pos + 2 > n {
            return None;
        }
        if ci.ifaces.len() < 32 {
            ci.ifaces.push(sanitize_j(cp_class(p, &cp, rd16be(p, pos) as u32), 160));
        }
        pos += 2;
    }
    for pass in 0..2 {
        if pos + 2 > n {
            return None;
        }
        let cnt = rd16be(p, pos);
        pos += 2;
        for _ in 0..cnt {
            if pos + 8 > n {
                return None;
            }
            let acc = rd16be(p, pos);
            let nm = rd16be(p, pos + 2) as u32;
            let ds = rd16be(p, pos + 4) as u32;
            let na = rd16be(p, pos + 6);
            pos += 8;
            let e = sanitize_j(cp_utf(p, &cp, nm), 80) + &sanitize_j(cp_utf(p, &cp, ds), 100);
            if pass == 0 {
                if ci.fields.len() < 300 {
                    ci.fields.push(e);
                }
            } else {
                if ci.methods.len() < 400 {
                    ci.methods.push(e);
                }
                if acc & 0x0100 != 0 {
                    ci.natives += 1;
                }
            }
            for _ in 0..na {
                if pos + 6 > n {
                    return None;
                }
                let al = rd32be(p, pos + 2) as usize;
                pos += 6;
                if pos + al > n {
                    return None;
                }
                pos += al;
            }
        }
    }
    if pos + 2 > n {
        return None;
    }
    let nca = rd16be(p, pos);
    pos += 2;
    for _ in 0..nca {
        if pos + 6 > n {
            return None;
        }
        let al = rd32be(p, pos + 2) as usize;
        pos += 6;
        if pos + al > n {
            return None;
        }
        pos += al;
    }
    ci.length = pos;
    for c in cp.iter().skip(1) {
        if c.tag == 8 && ci.strs.len() < 300 {
            ci.strs.push(sanitize_j(cp_utf(p, &cp, c.a as u32), 160));
        } else if c.tag == 7 && ci.refs.len() < 300 {
            ci.refs.push(sanitize_j(cp_utf(p, &cp, c.a as u32), 160));
        }
    }
    Some(ci)
}

mod inf {
    pub struct State<'a> {
        pub input: &'a [u8],
        pub incnt: usize,
        pub bitbuf: u32,
        pub bitcnt: i32,
        pub max_out: usize,
    }
    pub type R<T> = Result<T, i32>;
    #[derive(Clone)]
    pub struct Huff {
        pub count: [i16; 16],
        pub symbol: [i16; 288],
    }
    impl Huff {
        pub fn new() -> Huff {
            Huff {
                count: [0; 16],
                symbol: [0; 288],
            }
        }
    }
    pub fn bits(s: &mut State, need: i32) -> R<i32> {
        let mut val = s.bitbuf as i64;
        while s.bitcnt < need {
            if s.incnt >= s.input.len() {
                return Err(1);
            }
            val |= (s.input[s.incnt] as i64) << s.bitcnt;
            s.incnt += 1;
            s.bitcnt += 8;
        }
        s.bitbuf = (val >> need) as u32;
        s.bitcnt -= need;
        Ok((val & ((1i64 << need) - 1)) as i32)
    }
    pub fn decode(s: &mut State, h: &Huff) -> R<i32> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..=15usize {
            code |= bits(s, 1)?;
            let count = h.count[len] as i32;
            if code - count < first {
                return Ok(h.symbol.get((index + (code - first)) as usize).copied().unwrap_or(0) as i32);
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(2)
    }
    pub fn construct(h: &mut Huff, length: &[i16], n: usize) -> i32 {
        for len in 0..=15 {
            h.count[len] = 0;
        }
        for &l in length.iter().take(n) {
            h.count[l as usize] += 1;
        }
        if h.count[0] as usize == n {
            return 0;
        }
        let mut left = 1i32;
        for len in 1..=15 {
            left <<= 1;
            left -= h.count[len] as i32;
            if left < 0 {
                return left;
            }
        }
        let mut offs = [0i16; 16];
        offs[1] = 0;
        for len in 1..15 {
            offs[len + 1] = offs[len] + h.count[len];
        }
        for (sym, &l) in length.iter().enumerate().take(n) {
            if l != 0 {
                h.symbol[offs[l as usize] as usize] = sym as i16;
                offs[l as usize] += 1;
            }
        }
        left
    }
    const LENS: [i16; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227,
        258,
    ];
    const LEXT: [i16; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DISTS: [i16; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
        6145, 8193, 12289, 16385, 24577,
    ];
    const DEXT: [i16; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
    ];
    pub fn codes(s: &mut State, out: &mut Vec<u8>, lc: &Huff, dc: &Huff) -> R<()> {
        loop {
            let mut symbol = decode(s, lc)?;
            if symbol < 256 {
                if out.len() >= s.max_out {
                    return Err(3);
                }
                out.push(symbol as u8);
            } else if symbol > 256 {
                symbol -= 257;
                if symbol >= 29 {
                    return Err(4);
                }
                let len = LENS[symbol as usize] as i32 + bits(s, LEXT[symbol as usize] as i32)?;
                let ds = decode(s, dc)?;
                if !(0..30).contains(&ds) {
                    return Err(5);
                }
                let dist = DISTS[ds as usize] as usize + bits(s, DEXT[ds as usize] as i32)? as usize;
                if dist > out.len() {
                    return Err(6);
                }
                if out.len() + len as usize > s.max_out {
                    return Err(3);
                }
                let from = out.len() - dist;
                for k in 0..len as usize {
                    let b = out[from + k];
                    out.push(b);
                }
            }
            if symbol == 256 {
                return Ok(());
            }
        }
    }
    pub fn stored(s: &mut State, out: &mut Vec<u8>) -> R<()> {
        s.bitbuf = 0;
        s.bitcnt = 0;
        if s.incnt + 4 > s.input.len() {
            return Err(7);
        }
        let len = s.input[s.incnt] as usize | ((s.input[s.incnt + 1] as usize) << 8);
        let nlen = s.input[s.incnt + 2] as usize | ((s.input[s.incnt + 3] as usize) << 8);
        s.incnt += 4;
        if len != (!nlen & 0xFFFF) {
            return Err(8);
        }
        if s.incnt + len > s.input.len() {
            return Err(7);
        }
        if out.len() + len > s.max_out {
            return Err(3);
        }
        out.extend_from_slice(&s.input[s.incnt..s.incnt + len]);
        s.incnt += len;
        Ok(())
    }
    pub fn fixed(s: &mut State, out: &mut Vec<u8>) -> R<()> {
        let mut lengths = [0i16; 288];
        let mut lc = Huff::new();
        let mut dc = Huff::new();
        for (sym, l) in lengths.iter_mut().enumerate() {
            *l = if sym < 144 {
                8
            } else if sym < 256 {
                9
            } else if sym < 280 {
                7
            } else {
                8
            };
        }
        construct(&mut lc, &lengths, 288);
        for l in lengths.iter_mut().take(30) {
            *l = 5;
        }
        construct(&mut dc, &lengths, 30);
        codes(s, out, &lc, &dc)
    }
    pub fn dynamic(s: &mut State, out: &mut Vec<u8>) -> R<()> {
        const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
        let mut lengths = [0i16; 320];
        let mut lc = Huff::new();
        let mut dc = Huff::new();
        let nlen = bits(s, 5)? as usize + 257;
        let ndist = bits(s, 5)? as usize + 1;
        let ncode = bits(s, 4)? as usize + 4;
        if nlen > 286 || ndist > 30 {
            return Err(9);
        }
        let mut index = 0usize;
        while index < ncode {
            lengths[ORDER[index]] = bits(s, 3)? as i16;
            index += 1;
        }
        while index < 19 {
            lengths[ORDER[index]] = 0;
            index += 1;
        }
        if construct(&mut lc, &lengths, 19) != 0 {
            return Err(10);
        }
        index = 0;
        while index < nlen + ndist {
            let mut symbol = decode(s, &lc)?;
            if symbol < 16 {
                lengths[index] = symbol as i16;
                index += 1;
            } else {
                let mut len = 0i16;
                if symbol == 16 {
                    if index == 0 {
                        return Err(11);
                    }
                    len = lengths[index - 1];
                    symbol = 3 + bits(s, 2)?;
                } else if symbol == 17 {
                    symbol = 3 + bits(s, 3)?;
                } else {
                    symbol = 11 + bits(s, 7)?;
                }
                if index + symbol as usize > nlen + ndist {
                    return Err(12);
                }
                for _ in 0..symbol {
                    lengths[index] = len;
                    index += 1;
                }
            }
        }
        if lengths[256] == 0 {
            return Err(13);
        }
        let err = construct(&mut lc, &lengths, nlen);
        if err != 0 && (err < 0 || nlen as i32 != lc.count[0] as i32 + lc.count[1] as i32) {
            return Err(14);
        }
        let dl: Vec<i16> = lengths[nlen..nlen + ndist].to_vec();
        let err = construct(&mut dc, &dl, ndist);
        if err != 0 && (err < 0 || ndist as i32 != dc.count[0] as i32 + dc.count[1] as i32) {
            return Err(15);
        }
        codes(s, out, &lc, &dc)
    }
}

pub fn inflate_raw(input: &[u8], out: &mut Vec<u8>, max_out: usize) -> Option<usize> {
    let mut s = inf::State {
        input,
        incnt: 0,
        bitbuf: 0,
        bitcnt: 0,
        max_out,
    };
    let r = (|| -> inf::R<()> {
        loop {
            let last = inf::bits(&mut s, 1)?;
            let ty = inf::bits(&mut s, 2)?;
            match ty {
                0 => inf::stored(&mut s, out)?,
                1 => inf::fixed(&mut s, out)?,
                2 => inf::dynamic(&mut s, out)?,
                _ => return Err(99),
            }
            if last != 0 {
                return Ok(());
            }
        }
    })();
    match r {
        Ok(()) => Some(s.incnt),
        Err(_) => None,
    }
}

#[derive(Debug, Clone, Default)]
pub struct ZipEnt {
    pub name: String,
    pub method: u16,
    pub csize: u32,
    pub usize_: u32,
    pub data_off: usize,
}

pub fn zip_list_at(p: &[u8], eocd: usize) -> Option<(Vec<ZipEnt>, usize)> {
    let n = p.len();
    let mut out = Vec::new();
    if eocd + 22 > n {
        return None;
    }
    let total = rd16(p, eocd + 10);
    let cd_size = rd32(p, eocd + 12) as u64;
    let cd_off = rd32(p, eocd + 16) as u64;
    if total == 0 || cd_size + cd_off > eocd as u64 {
        return None;
    }
    let zip_start = eocd - cd_size as usize - cd_off as usize;
    let mut pos = zip_start + cd_off as usize;
    if pos + 46 > n || rd32(p, pos) != 0x02014B50 {
        return None;
    }
    let mut i = 0u32;
    while i < total as u32 && i < 20000 {
        i += 1;
        if pos + 46 > n || rd32(p, pos) != 0x02014B50 {
            break;
        }
        let mut e = ZipEnt {
            method: rd16(p, pos + 10),
            csize: rd32(p, pos + 20),
            usize_: rd32(p, pos + 24),
            ..Default::default()
        };
        let nl = rd16(p, pos + 28) as usize;
        let el = rd16(p, pos + 30) as usize;
        let cl = rd16(p, pos + 32) as usize;
        let lho = rd32(p, pos + 42) as usize;
        if pos + 46 + nl > n {
            break;
        }
        e.name = sanitize_j(&p[pos + 46..pos + 46 + nl], 200);
        let lp = zip_start + lho;
        if lp + 30 <= n && rd32(p, lp) == 0x04034B50 {
            let ds = lp + 30 + rd16(p, lp + 26) as usize + rd16(p, lp + 28) as usize;
            if ds <= n && ds as u64 + e.csize as u64 <= n as u64 {
                e.data_off = ds;
                out.push(e);
            }
        }
        pos += 46 + nl + el + cl;
    }
    if out.is_empty() {
        None
    } else {
        Some((out, zip_start))
    }
}

pub fn zip_extract(p: &[u8], e: &ZipEnt, out: &mut Vec<u8>, max_out: usize) -> bool {
    out.clear();
    let n = p.len();
    if e.data_off > n || e.data_off as u64 + e.csize as u64 > n as u64 {
        return false;
    }
    if e.method == 0 {
        if e.csize as usize > max_out {
            return false;
        }
        out.extend_from_slice(&p[e.data_off..e.data_off + e.csize as usize]);
        return true;
    }
    if e.method == 8 {
        return inflate_raw(&p[e.data_off..e.data_off + e.csize as usize], out, max_out).is_some();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inflate_stored_and_fixed() {
        let d = [0x01, 0x03, 0x00, 0xFC, 0xFF, b'a', b'b', b'c'];
        let mut o = Vec::new();
        assert_eq!(inflate_raw(&d, &mut o, 100), Some(8));
        assert_eq!(o, b"abc");
        let d = [0x4B, 0x04, 0x00];
        let mut o = Vec::new();
        assert!(inflate_raw(&d, &mut o, 100).is_some());
        assert_eq!(o, b"a");
        let mut o = Vec::new();
        assert!(inflate_raw(&d, &mut o, 0).is_none());
        assert!(inflate_raw(&[0xFF], &mut Vec::new(), 10).is_none());
    }

    #[test]
    fn class_garbage() {
        assert!(parse_class(&[0u8; 40]).is_none());
        let mut c = vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52, 0, 2];
        c.resize(40, 0);
        assert!(parse_class(&c).is_none());
    }
}
