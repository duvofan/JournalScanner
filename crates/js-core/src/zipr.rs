use crate::util::*;
use flate2::{Decompress, FlushDecompress, Status};

fn r16(d: &[u8], o: usize) -> u16 {
    match d.get(o..o.saturating_add(2)) {
        Some(b) => u16::from_le_bytes([b[0], b[1]]),
        None => 0,
    }
}
fn r32(d: &[u8], o: usize) -> u32 {
    match d.get(o..o.saturating_add(4)) {
        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        None => 0,
    }
}
fn r64(d: &[u8], o: usize) -> u64 {
    match d.get(o..o.saturating_add(8)) {
        Some(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        None => 0,
    }
}
fn crc32_of(d: &[u8]) -> u32 {
    crc32fast::hash(d)
}

const CP437_HI: [u16; 128] = [
    0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7, 0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC,
    0x00C4, 0x00C5, 0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9, 0x00FF, 0x00D6, 0x00DC, 0x00A2,
    0x00A3, 0x00A5, 0x20A7, 0x0192, 0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA, 0x00BF, 0x2310,
    0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB, 0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510, 0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C,
    0x255E, 0x255F, 0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559,
    0x2558, 0x2552, 0x2553, 0x256B, 0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580, 0x03B1, 0x00DF,
    0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4, 0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
    0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248, 0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2,
    0x25A0, 0x00A0,
];

fn cp437(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if c < 0x80 {
                c as char
            } else {
                char::from_u32(CP437_HI[(c - 0x80) as usize] as u32).unwrap_or('\u{FFFD}')
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct ZEntry {
    pub name: String,
    pub flags: u16,
    pub method: u16,
    pub crc: u32,
    pub csize: u64,
    pub usize: u64,
    pub hoff: u64,
}
impl ZEntry {
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

#[derive(Default)]
struct EndRec {
    size_cd: u64,
    offset_cd: u64,
    location: u64,
}

fn end_rec64(d: &[u8], offset: i64, er: &mut EndRec) -> bool {
    let loc = offset - 20;
    if loc < 0 {
        return true;
    }
    let loc = loc as usize;
    if d.get(loc..loc + 4) != Some(b"PK\x06\x07".as_slice()) {
        return true;
    }
    let diskno = r32(d, loc + 4);
    let reloff = r64(d, loc + 8);
    let disks = r32(d, loc + 16);
    if diskno != 0 || disks > 1 {
        return false;
    }
    let off64 = loc as i64 - 56;
    if reloff as i64 > off64 {
        return false;
    }
    let mut extrasz = off64.wrapping_sub(reloff as i64);
    let mut q: Option<usize> = None;
    if reloff.wrapping_add(56) <= d.len() as u64 {
        q = Some(reloff as usize);
    }
    let q_has_magic = |q: Option<usize>| q.is_some_and(|o| d.get(o..o + 4) == Some(b"PK\x06\x06".as_slice()));
    if !q_has_magic(q) && reloff as i64 != off64 {
        if off64 < 0 {
            return false;
        }
        q = Some(off64 as usize);
        extrasz = 0;
    }
    let q = match q {
        Some(o) if q_has_magic(Some(o)) => o,
        _ => return false,
    };
    let sz = r64(d, q + 4);
    let dirsize = r64(d, q + 40);
    let diroffset = r64(d, q + 48);
    if diroffset.wrapping_add(dirsize) != reloff || (sz as i64).wrapping_add(12) != 56i64.wrapping_add(extrasz) {
        return false;
    }
    er.size_cd = dirsize;
    er.offset_cd = diroffset;
    er.location = off64.wrapping_sub(extrasz) as u64;
    true
}

fn end_rec(d: &[u8], er: &mut EndRec) -> bool {
    let n = d.len();
    if n < 22 {
        return false;
    }
    let base = n - 22;
    if d[base..base + 4] == *b"PK\x05\x06" && d[base + 20] == 0 && d[base + 21] == 0 {
        er.size_cd = r32(d, base + 12) as u64;
        er.offset_cd = r32(d, base + 16) as u64;
        er.location = base as u64;
        return end_rec64(d, base as i64, er);
    }
    let maxc = if n > 65535 + 22 { n - 65535 - 22 } else { 0 };
    let tail = &d[maxc..];
    let s = match tail.windows(4).rposition(|w| w == b"PK\x05\x06") {
        Some(s) => s,
        None => return false,
    };
    if s + 22 > tail.len() {
        return false;
    }
    let p = maxc + s;
    er.size_cd = r32(d, p + 12) as u64;
    er.offset_cd = r32(d, p + 16) as u64;
    er.location = p as u64;
    end_rec64(d, p as i64, er)
}

#[derive(Debug, Default)]
pub struct ZipReader<'a> {
    d: &'a [u8],
    ents: Vec<ZEntry>,
    err: String,
}
impl<'a> ZipReader<'a> {
    pub fn new() -> Self {
        ZipReader {
            d: &[],
            ents: Vec::new(),
            err: String::new(),
        }
    }
    pub fn open(&mut self, data: &'a [u8]) -> bool {
        self.d = data;
        self.ents.clear();
        self.err.clear();
        let mut er = EndRec::default();
        if !end_rec(data, &mut er) {
            self.err = "File is not a zip file".to_string();
            return false;
        }
        let concat = (er.location as i64)
            .wrapping_sub(er.size_cd as i64)
            .wrapping_sub(er.offset_cd as i64);
        let start_dir = (er.offset_cd as i64).wrapping_add(concat);
        if start_dir < 0 {
            self.err = "Bad offset for central directory".to_string();
            return false;
        }
        if start_dir as u64 > data.len() as u64 {
            self.err = "Truncated central directory".to_string();
            return false;
        }
        let sd = start_dir as usize;
        let cdlen = er.size_cd.min((data.len() - sd) as u64) as usize;
        let cd = &data[sd..sd + cdlen];
        let mut total: u64 = 0;
        let mut pos = 0usize;
        while total < er.size_cd {
            if pos + 46 > cd.len() {
                self.err = "Truncated central directory".to_string();
                return false;
            }
            if cd[pos..pos + 4] != *b"PK\x01\x02" {
                self.err = "Bad magic number for central directory".to_string();
                return false;
            }
            let flags = r16(cd, pos + 8);
            let method = r16(cd, pos + 10);
            let crc = r32(cd, pos + 16);
            let mut csize = r32(cd, pos + 20) as u64;
            let mut usize_ = r32(cd, pos + 24) as u64;
            let nlen = r16(cd, pos + 28) as usize;
            let xlen = r16(cd, pos + 30) as usize;
            let clen = r16(cd, pos + 32) as usize;
            let mut hoff = r32(cd, pos + 42) as u64;
            pos += 46;
            let sub = |from: usize, n: usize| -> &[u8] {
                let f = from.min(cd.len());
                let e = f.saturating_add(n).min(cd.len());
                &cd[f..e]
            };
            let rawname = sub(pos, nlen);
            pos += nlen;
            let extra = sub(pos, xlen);
            pos += xlen;
            pos += clen;
            let mut name: String;
            if flags & 0x800 != 0 {
                match std::str::from_utf8(rawname) {
                    Ok(s) => name = s.to_string(),
                    Err(_) => {
                        self.err = "invalid utf-8 file name".to_string();
                        return false;
                    }
                }
            } else {
                name = cp437(rawname);
            }
            let name_crc = crc32_of(rawname);
            let mut ex = extra;
            while ex.len() >= 4 {
                let tp = r16(ex, 0);
                let ln = r16(ex, 2) as usize;
                if ln + 4 > ex.len() {
                    self.err = format!("Corrupt extra field {:04x} (size={})", tp, ln);
                    return false;
                }
                let dat = &ex[4..4 + ln];
                if tp == 0x0001 {
                    let mut k = 0usize;
                    if usize_ == 0xFFFF_FFFF {
                        if k + 8 > dat.len() {
                            self.err = "Corrupt zip64 extra field".to_string();
                            return false;
                        }
                        usize_ = r64(dat, k);
                        k += 8;
                    }
                    if csize == 0xFFFF_FFFF {
                        if k + 8 > dat.len() {
                            self.err = "Corrupt zip64 extra field".to_string();
                            return false;
                        }
                        csize = r64(dat, k);
                        k += 8;
                    }
                    if hoff == 0xFFFF_FFFF {
                        if k + 8 > dat.len() {
                            self.err = "Corrupt zip64 extra field".to_string();
                            return false;
                        }
                        hoff = r64(dat, k);
                    }
                } else if tp == 0x7075 {
                    if dat.len() < 5 {
                        self.err = "Corrupt unicode path extra field (0x7075)".to_string();
                        return false;
                    }
                    let ver = dat[0];
                    let ncrc = r32(dat, 1);
                    if ver == 1 && ncrc == name_crc {
                        let un = &dat[5..];
                        match std::str::from_utf8(un) {
                            Ok(s) => {
                                if !un.is_empty() {
                                    name = s.to_string();
                                }
                            }
                            Err(_) => {
                                self.err = "Corrupt unicode path extra field (0x7075)".to_string();
                                return false;
                            }
                        }
                    }
                }
                ex = &ex[ln + 4..];
            }
            if let Some(z) = name.find('\0') {
                name.truncate(z);
            }
            let name = name.replace('\\', "/");
            self.ents.push(ZEntry {
                name,
                flags,
                method,
                crc,
                csize,
                usize: usize_,
                hoff: hoff.wrapping_add(concat as u64),
            });
            total += 46u64 + nlen as u64 + xlen as u64 + clen as u64;
        }
        true
    }
    pub fn entries(&self) -> &[ZEntry] {
        &self.ents
    }
    pub fn read(
        &self,
        e: &ZEntry,
        out: &mut Bytes,
        err: Option<&mut String>,
        crc_ok: Option<&mut bool>,
        limit: u64,
    ) -> bool {
        out.clear();
        let fail = |err: Option<&mut String>, m: &str| {
            if let Some(er) = err {
                *er = m.to_string();
            }
            false
        };
        let dl = self.d.len() as u64;
        if e.hoff.saturating_add(30) > dl {
            return fail(err, "Truncated file header");
        }
        let h = e.hoff as usize;
        if self.d[h..h + 4] != *b"PK\x03\x04" {
            return fail(err, "Bad magic number for file header");
        }
        let nlen = r16(self.d, h + 26) as u64;
        let xlen = r16(self.d, h + 28) as u64;
        if e.flags & 0x20 != 0 {
            return fail(err, "compressed patched data (flag bit 5)");
        }
        if e.flags & 0x40 != 0 {
            return fail(err, "strong encryption (flag bit 6)");
        }
        if e.flags & 0x1 != 0 {
            return fail(err, "File is encrypted, password required for extraction");
        }
        let start = e.hoff + 30 + nlen + xlen;
        if start > dl {
            return fail(err, "Truncated file data");
        }
        let avail = dl - start;
        let clen = e.csize.min(avail) as usize;
        let comp = &self.d[start as usize..start as usize + clen];
        match e.method {
            0 => {
                if (comp.len() as u64) < e.csize {
                    return fail(err, "Truncated file data");
                }
                let n = (comp.len() as u64).min(limit) as usize;
                out.extend_from_slice(&comp[..n]);
            }
            8 => {
                let mut ended = false;
                let ok = inflate_raw(comp, out, limit, Some(&mut ended));
                if !ok {
                    return fail(err, "Error -3 while decompressing data");
                }
                if !ended && (out.len() as u64) < limit {
                    return fail(err, "Compressed file ended before the end-of-stream marker was reached");
                }
            }
            12 => {
                if !unbz2(comp, out, limit) {
                    return fail(err, "Invalid data stream");
                }
            }
            14 => {
                if !zip_lzma(comp, out, limit) {
                    return fail(err, "Corrupt input data");
                }
            }
            _ => return fail(err, "That compression method is not supported"),
        }
        if let Some(c) = crc_ok {
            *c = crc32_of(out) == e.crc;
        }
        true
    }
    pub fn error(&self) -> &str {
        &self.err
    }
    pub fn testzip(&self) -> bool {
        for e in &self.ents {
            let mut b = Bytes::new();
            let mut c = false;
            if !self.read(e, &mut b, None, Some(&mut c), 1u64 << 34) {
                return false;
            }
            if !c {
                return false;
            }
        }
        true
    }
}

pub fn zip_opens(data: &[u8], names: Option<&mut Vec<String>>) -> bool {
    let mut z = ZipReader::new();
    if !z.open(data) {
        return false;
    }
    if let Some(n) = names {
        n.clear();
        n.extend(z.entries().iter().map(|e| e.name.clone()));
    }
    true
}

fn w16(b: &mut Bytes, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut Bytes, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}

#[derive(Debug, Default)]
pub struct ZipWriter {
    buf: Bytes,
    cd: Bytes,
    n: usize,
}
impl ZipWriter {
    pub fn new() -> Self {
        ZipWriter::default()
    }
    pub fn add(&mut self, name: &str, data: &[u8]) {
        let crc = crc32_of(data);
        let off = self.buf.len() as u64;
        let ascii = name.bytes().all(|c| c < 0x80);
        let flags: u16 = if ascii { 0 } else { 0x800 };
        let dsz = data.len() as u64;
        let z64 = dsz >= 0xFFFF_FFFF || off >= 0xFFFF_FFFF;
        let nb = name.as_bytes();
        let (buf, cd) = (&mut self.buf, &mut self.cd);
        buf.extend_from_slice(b"PK\x03\x04");
        w16(buf, if z64 { 45 } else { 20 });
        w16(buf, flags);
        w16(buf, 0);
        w16(buf, 0);
        w16(buf, (1 << 5) | 1); // 1980-01-01
        w32(buf, crc);
        w32(buf, if z64 { 0xFFFF_FFFF } else { dsz as u32 });
        w32(buf, if z64 { 0xFFFF_FFFF } else { dsz as u32 });
        w16(buf, nb.len() as u16);
        w16(buf, if z64 { 20 } else { 0 });
        buf.extend_from_slice(nb);
        if z64 {
            w16(buf, 1);
            w16(buf, 16);
            for _ in 0..2 {
                w32(buf, dsz as u32);
                w32(buf, (dsz >> 32) as u32);
            }
        }
        buf.extend_from_slice(data);
        cd.extend_from_slice(b"PK\x01\x02");
        w16(cd, 20);
        w16(cd, if z64 { 45 } else { 20 });
        w16(cd, flags);
        w16(cd, 0);
        w16(cd, 0);
        w16(cd, (1 << 5) | 1);
        w32(cd, crc);
        w32(cd, if z64 { 0xFFFF_FFFF } else { dsz as u32 });
        w32(cd, if z64 { 0xFFFF_FFFF } else { dsz as u32 });
        w16(cd, nb.len() as u16);
        w16(cd, if z64 { 28 } else { 0 });
        w16(cd, 0);
        w16(cd, 0);
        w16(cd, 0);
        w32(cd, 0);
        w32(cd, if z64 { 0xFFFF_FFFF } else { off as u32 });
        cd.extend_from_slice(nb);
        if z64 {
            w16(cd, 1);
            w16(cd, 24);
            for _ in 0..2 {
                w32(cd, dsz as u32);
                w32(cd, (dsz >> 32) as u32);
            }
            w32(cd, off as u32);
            w32(cd, (off >> 32) as u32);
        }
        self.n += 1;
    }
    pub fn finish(&mut self) -> Bytes {
        let cdoff = self.buf.len() as u64;
        let mut out = std::mem::take(&mut self.buf);
        out.extend_from_slice(&self.cd);
        let n = self.n as u64;
        let cdsz = self.cd.len() as u64;
        let z64 = cdoff >= 0xFFFF_FFFF || self.n >= 0xFFFF;
        if z64 {
            let z64off = out.len() as u64;
            out.extend_from_slice(b"PK\x06\x06");
            w32(&mut out, 44);
            w32(&mut out, 0);
            w16(&mut out, 45);
            w16(&mut out, 45);
            w32(&mut out, 0);
            w32(&mut out, 0);
            for _ in 0..2 {
                w32(&mut out, n as u32);
                w32(&mut out, (n >> 32) as u32);
            }
            w32(&mut out, cdsz as u32);
            w32(&mut out, (cdsz >> 32) as u32);
            w32(&mut out, cdoff as u32);
            w32(&mut out, (cdoff >> 32) as u32);
            out.extend_from_slice(b"PK\x06\x07");
            w32(&mut out, 0);
            w32(&mut out, z64off as u32);
            w32(&mut out, (z64off >> 32) as u32);
            w32(&mut out, 1);
        }
        out.extend_from_slice(b"PK\x05\x06");
        w16(&mut out, 0);
        w16(&mut out, 0);
        w16(&mut out, n.min(0xFFFF) as u16);
        w16(&mut out, n.min(0xFFFF) as u16);
        w32(&mut out, cdsz.min(0xFFFF_FFFF) as u32);
        w32(&mut out, cdoff.min(0xFFFF_FFFF) as u32);
        w16(&mut out, 0);
        self.cd.clear();
        out
    }
    pub fn count(&self) -> usize {
        self.n
    }
}

const CHUNK: usize = 1 << 16;

struct RawInflate {
    d: Decompress,
    buf: Vec<u8>,
}

enum Step {
    Done(usize, usize, Result<Status, ()>),
}

impl RawInflate {
    fn new() -> Self {
        RawInflate {
            d: Decompress::new(false),
            buf: vec![0u8; CHUNK],
        }
    }
    fn step(&mut self, input: &[u8]) -> Step {
        let (bi, bo) = (self.d.total_in(), self.d.total_out());
        let r = self.d.decompress(input, &mut self.buf, FlushDecompress::None);
        let consumed = (self.d.total_in() - bi) as usize;
        let produced = (self.d.total_out() - bo) as usize;
        Step::Done(
            produced.min(self.buf.len()),
            consumed.min(input.len()),
            r.map_err(|_| ()),
        )
    }
}

pub fn inflate_raw(data: &[u8], out: &mut Bytes, limit: u64, ended: Option<&mut bool>) -> bool {
    let mut zs = RawInflate::new();
    let mut input = data;
    let mut end = false;
    let mut ok = true;
    loop {
        let Step::Done(produced, consumed, r) = zs.step(input);
        input = &input[consumed..];
        if produced > 0 {
            if out.len() as u64 + produced as u64 > limit {
                let n = (limit.saturating_sub(out.len() as u64)) as usize;
                out.extend_from_slice(&zs.buf[..n.min(produced)]);
                break;
            }
            out.extend_from_slice(&zs.buf[..produced]);
        }
        match r {
            Ok(Status::StreamEnd) => {
                end = true;
                break;
            }
            Ok(Status::BufError) => {
                if input.is_empty() && produced == 0 {
                    break;
                }
            }
            Ok(Status::Ok) => {}
            Err(()) => {
                ok = false;
                break;
            }
        }
        if input.is_empty() && produced == 0 {
            break;
        }
        if consumed == 0 && produced == 0 {
            break;
        }
    }
    if let Some(e) = ended {
        *e = end;
    }
    ok
}

fn zip_lzma(data: &[u8], out: &mut Bytes, limit: u64) -> bool {
    use liblzma::stream::{Action, Filters, Status as XS, Stream};
    if data.len() < 4 {
        return false;
    }
    let psz = r16(data, 2) as usize;
    if data.len() < 4 + psz {
        return false;
    }
    let mut filters = Filters::new();
    if filters.lzma1_properties(&data[4..4 + psz]).is_err() {
        return false;
    }
    let mut s = match Stream::new_raw_decoder(&filters) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut input = &data[4 + psz..];
    let mut buf = vec![0u8; CHUNK];
    let mut ok = true;
    loop {
        let (bi, bo) = (s.total_in(), s.total_out());
        let r = s.process(input, &mut buf, Action::Finish);
        let consumed = ((s.total_in() - bi) as usize).min(input.len());
        let produced = ((s.total_out() - bo) as usize).min(buf.len());
        input = &input[consumed..];
        if out.len() as u64 + produced as u64 > limit {
            let n = (limit.saturating_sub(out.len() as u64)) as usize;
            out.extend_from_slice(&buf[..n.min(produced)]);
            break;
        }
        out.extend_from_slice(&buf[..produced]);
        match r {
            Ok(XS::StreamEnd) => break,
            Ok(XS::Ok) => {}
            Ok(XS::MemNeeded) => {
                ok = !out.is_empty();
                break;
            }
            Ok(_) | Err(_) => {
                ok = false;
                break;
            }
        }
        if produced == 0 && input.is_empty() {
            break;
        }
        if consumed == 0 && produced == 0 {
            break;
        }
    }
    ok
}

pub fn gunzip(data: &[u8], out: &mut Bytes, limit: u64, complete: Option<&mut bool>) -> bool {
    let mut complete = complete;
    let mut pos = 0usize;
    let mut any = false;
    if let Some(c) = complete.as_deref_mut() {
        *c = false;
    }
    while pos < data.len() {
        let mut z = pos;
        while z < data.len() && data[z] == 0 {
            z += 1;
        }
        if z >= data.len() {
            break;
        }
        pos = z;
        if data.len() - pos < 2 || data[pos] != 0x1f || data[pos + 1] != 0x8b {
            return any && out.len() as u64 >= limit; // Not a gzipped file
        }
        let body = match gzip_header_len(&data[pos..]) {
            Some(n) => pos + n,
            None => return false, // başlık hatalı ya da eksik
        };
        let mut zs = RawInflate::new();
        let mut input = &data[body..];
        let mut hasher = crc32fast::Hasher::new();
        let mut total: u32 = 0;
        let mut ended = false;
        loop {
            let Step::Done(produced, consumed, r) = zs.step(input);
            input = &input[consumed..];
            if produced > 0 {
                if out.len() as u64 + produced as u64 >= limit {
                    let n = (limit.saturating_sub(out.len() as u64)) as usize;
                    out.extend_from_slice(&zs.buf[..n.min(produced)]);
                    return true;
                }
                out.extend_from_slice(&zs.buf[..produced]);
                hasher.update(&zs.buf[..produced]);
                total = total.wrapping_add(produced as u32);
            }
            match r {
                Ok(Status::StreamEnd) => {
                    ended = true;
                    break;
                }
                Ok(Status::Ok) => {}
                Ok(Status::BufError) => {
                    if produced == 0 {
                        return false;
                    }
                }
                Err(()) => return false,
            }
            if input.is_empty() && produced == 0 {
                break;
            }
            if consumed == 0 && produced == 0 {
                break;
            }
        }
        if !ended {
            return false; // eksik akış (EOFError)
        }
        if input.len() < 8 {
            return false;
        }
        if r32(input, 0) != hasher.finalize() || r32(input, 4) != total {
            return false;
        }
        input = &input[8..];
        pos = data.len() - input.len();
        any = true;
    }
    if let Some(c) = complete {
        *c = true;
    }
    any
}

fn gzip_header_len(d: &[u8]) -> Option<usize> {
    if d.len() < 10 {
        return None;
    }
    if d[2] != 8 {
        return None; // unknown compression method
    }
    let flg = d[3];
    if flg & 0xe0 != 0 {
        return None; // unknown header flags set
    }
    let mut p = 10usize;
    if flg & 4 != 0 {
        let xl = d.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)?;
        p += 2 + xl;
        if p > d.len() {
            return None;
        }
    }
    for bit in [8u8, 16u8] {
        if flg & bit != 0 {
            let z = d.get(p..)?.iter().position(|&c| c == 0)?;
            p += z + 1;
        }
    }
    if flg & 2 != 0 {
        let hc = d.get(p..p + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))?;
        if (crc32_of(&d[..p]) & 0xffff) as u16 != hc {
            return None; // header crc mismatch
        }
        p += 2;
    }
    Some(p)
}

pub fn unxz(data: &[u8], out: &mut Bytes, limit: u64) -> bool {
    use liblzma::stream::{Action, Status as XS, Stream};
    let mut s = match Stream::new_auto_decoder(u64::MAX, 0) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut input = data;
    let mut buf = vec![0u8; CHUNK];
    let mut ok = true;
    loop {
        let (bi, bo) = (s.total_in(), s.total_out());
        let r = s.process(input, &mut buf, Action::Run);
        let consumed = ((s.total_in() - bi) as usize).min(input.len());
        let produced = ((s.total_out() - bo) as usize).min(buf.len());
        input = &input[consumed..];
        if out.len() as u64 + produced as u64 >= limit {
            let n = (limit.saturating_sub(out.len() as u64)) as usize;
            out.extend_from_slice(&buf[..n.min(produced)]);
            break;
        }
        out.extend_from_slice(&buf[..produced]);
        match r {
            Ok(XS::StreamEnd) => break,
            Ok(XS::Ok) => {}
            Ok(_) | Err(_) => {
                ok = false;
                break;
            }
        }
        if input.is_empty() && produced == 0 {
            break; // girdi bitti (eksik akış): Python hata vermez, eldekini döner
        }
        if consumed == 0 && produced == 0 {
            break;
        }
    }
    ok
}

pub fn unbz2(data: &[u8], out: &mut Bytes, limit: u64) -> bool {
    use bzip2::Status as BS;
    let mut s = bzip2::Decompress::new(false);
    let mut input = data;
    let mut buf = vec![0u8; CHUNK];
    let mut ok = true;
    loop {
        let (bi, bo) = (s.total_in(), s.total_out());
        let r = s.decompress(input, &mut buf);
        let consumed = ((s.total_in() - bi) as usize).min(input.len());
        let produced = ((s.total_out() - bo) as usize).min(buf.len());
        input = &input[consumed..];
        if out.len() as u64 + produced as u64 >= limit {
            let n = (limit.saturating_sub(out.len() as u64)) as usize;
            out.extend_from_slice(&buf[..n.min(produced)]);
            break;
        }
        out.extend_from_slice(&buf[..produced]);
        match r {
            Ok(BS::StreamEnd) => break,
            Ok(BS::Ok) | Ok(BS::RunOk) | Ok(BS::FlushOk) | Ok(BS::FinishOk) => {}
            Ok(BS::MemNeeded) | Err(_) => {
                ok = false;
                break;
            }
        }
        if input.is_empty() && produced == 0 {
            break;
        }
        if consumed == 0 && produced == 0 {
            break;
        }
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn deflate(d: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(d).unwrap();
        e.finish().unwrap()
    }
    fn gz(d: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(d).unwrap();
        e.finish().unwrap()
    }
    fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| ((i * 31 + i / 7) % 251) as u8).collect()
    }

    #[test]
    fn yazici_okuyucu_dongusu() {
        let mut w = ZipWriter::new();
        w.add("a.txt", b"merhaba");
        w.add("dir/", b"");
        w.add("türkçe.txt", b"x");
        assert_eq!(w.count(), 3);
        let z = w.finish();
        let mut names = Vec::new();
        assert!(zip_opens(&z, Some(&mut names)));
        assert_eq!(names, ["a.txt", "dir/", "türkçe.txt"]);
        let mut r = ZipReader::new();
        assert!(r.open(&z));
        assert!(r.entries()[1].is_dir());
        let mut out = Vec::new();
        let mut crc = false;
        assert!(r.read(&r.entries()[0], &mut out, None, Some(&mut crc), 1 << 34));
        assert_eq!(out, b"merhaba");
        assert!(crc);
        assert!(r.testzip());
    }

    #[test]
    fn bos_zip_ve_bozuk() {
        let z = ZipWriter::new().finish();
        assert_eq!(z.len(), 22);
        assert!(zip_opens(&z, None));
        assert!(!zip_opens(b"", None));
        assert!(!zip_opens(b"PK\x03\x04 hello", None));
        let mut r = ZipReader::new();
        assert!(!r.open(&[0u8; 100]));
        assert_eq!(r.error(), "File is not a zip file");
        let mut w = ZipWriter::new();
        w.add("a", b"1");
        let mut z = w.finish();
        let n = z.len();
        z.truncate(n - 30);
        assert!(!zip_opens(&z, None));
    }

    #[test]
    fn deflate_girdisi_ve_crc() {
        let data = sample(100_000);
        let comp = deflate(&data);
        let mut z = Vec::new();
        z.extend_from_slice(b"PK\x03\x04");
        z.extend_from_slice(&[20, 0, 0, 0, 8, 0, 0, 0, 0x21, 0]);
        z.extend_from_slice(&crc32fast::hash(&data).to_le_bytes());
        z.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&[1, 0, 0, 0]);
        z.push(b'f');
        z.extend_from_slice(&comp);
        let cd_off = z.len();
        z.extend_from_slice(b"PK\x01\x02");
        z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 8, 0, 0, 0, 0x21, 0]);
        z.extend_from_slice(&crc32fast::hash(&data).to_le_bytes());
        z.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        z.push(b'f');
        let cd_len = z.len() - cd_off;
        z.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
        z.extend_from_slice(&(cd_len as u32).to_le_bytes());
        z.extend_from_slice(&(cd_off as u32).to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        let mut r = ZipReader::new();
        assert!(r.open(&z));
        let e = r.entries()[0].clone();
        assert_eq!((e.method, e.usize), (8, data.len() as u64));
        let mut out = Vec::new();
        let mut ok = false;
        assert!(r.read(&e, &mut out, None, Some(&mut ok), 1 << 34));
        assert_eq!(out, data);
        assert!(ok);
        assert!(r.read(&e, &mut out, None, None, 10));
        assert_eq!(out, &data[..10]);
        let mut z2 = z.clone();
        z2[cd_off + 16] ^= 0xFF;
        let mut r2 = ZipReader::new();
        assert!(r2.open(&z2));
        let e2 = r2.entries()[0].clone();
        assert!(r2.read(&e2, &mut out, None, Some(&mut ok), 1 << 34));
        assert!(!ok);
        let mut e3 = e.clone();
        e3.csize = (comp.len() / 2) as u64;
        let mut err = String::new();
        assert!(!r.read(&e3, &mut out, Some(&mut err), None, 1 << 34));
        assert!(!err.is_empty());
        let mut e4 = e.clone();
        e4.method = 93;
        assert!(!r.read(&e4, &mut out, Some(&mut err), None, 1 << 34));
        assert_eq!(err, "That compression method is not supported");
    }

    #[test]
    fn bozuk_ofsetler_panik_etmez() {
        let mut w = ZipWriter::new();
        w.add("a", b"hello");
        let z = w.finish();
        let r_ok = {
            let mut r = ZipReader::new();
            assert!(r.open(&z));
            r.entries()[0].clone()
        };
        let mut r = ZipReader::new();
        assert!(r.open(&z));
        let mut out = Vec::new();
        for hoff in [u64::MAX, u64::MAX - 20, z.len() as u64, z.len() as u64 - 5, 1 << 40] {
            let mut e = r_ok.clone();
            e.hoff = hoff;
            assert!(!r.read(&e, &mut out, None, None, 100));
        }
        for cut in 0..z.len() {
            let _ = zip_opens(&z[..cut], None);
            let mut zz = z.clone();
            zz[cut] ^= 0xA5;
            let mut rr = ZipReader::new();
            if rr.open(&zz) {
                let _ = rr.testzip();
            }
        }
    }

    #[test]
    fn on_ek_birlesik_zip_ofseti() {
        let mut w = ZipWriter::new();
        w.add("a", b"hello");
        let z = w.finish();
        let mut pre = vec![0x41u8; 37];
        pre.extend_from_slice(&z);
        let mut r = ZipReader::new();
        assert!(r.open(&pre));
        let mut out = Vec::new();
        assert!(r.read(&r.entries()[0], &mut out, None, None, 100));
        assert_eq!(out, b"hello");
    }

    #[test]
    fn ad_cozumleme() {
        let mut w = ZipWriter::new();
        w.add("a\\b.txt", b"x");
        let z = w.finish();
        let mut names = Vec::new();
        assert!(zip_opens(&z, Some(&mut names)));
        assert_eq!(names, ["a/b.txt"]);
        let mut w = ZipWriter::new();
        w.add("a\0b.txt", b"x");
        let z = w.finish();
        assert!(zip_opens(&z, Some(&mut names)));
        assert_eq!(names, ["a"]);
        assert_eq!(cp437(&[0x80, 0x41, 0xFF]), "\u{C7}A\u{A0}");
    }

    #[test]
    fn gunzip_cesitleri() {
        let data = sample(200_000);
        let mut out = Vec::new();
        let mut complete = false;
        assert!(gunzip(&gz(&data), &mut out, 1 << 30, Some(&mut complete)));
        assert_eq!(out, data);
        assert!(complete);
        let mut two = gz(b"abc");
        two.extend_from_slice(&gz(b"def"));
        two.extend_from_slice(&[0, 0, 0]);
        out.clear();
        assert!(gunzip(&two, &mut out, 1 << 30, Some(&mut complete)));
        assert_eq!(out, b"abcdef");
        assert!(complete);
        out.clear();
        complete = true;
        assert!(gunzip(&gz(&data), &mut out, 1024, Some(&mut complete)));
        assert_eq!(out, &data[..1024]);
        assert!(!complete);
        let g = gz(&data);
        out.clear();
        assert!(!gunzip(&g[..g.len() / 2], &mut out, 1 << 30, None));
        assert!(!out.is_empty());
        out.clear();
        assert!(!gunzip(&g[..g.len() - 3], &mut out, 1 << 30, None));
        let mut bad = g.clone();
        let n = bad.len();
        bad[n - 6] ^= 1;
        out.clear();
        assert!(!gunzip(&bad, &mut out, 1 << 30, None));
        out.clear();
        assert!(!gunzip(b"hello world", &mut out, 1 << 30, None));
        assert!(!gunzip(b"", &mut out, 1 << 30, None));
        assert!(!gunzip(&[0, 0, 0], &mut out, 1 << 30, None));
        let mut junk = gz(b"abc");
        junk.extend_from_slice(b"JUNKJUNK");
        out.clear();
        assert!(!gunzip(&junk, &mut out, 1 << 30, None));
        assert_eq!(out, b"abc");
        let mut named = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3];
        named.extend_from_slice(b"n.txt\0");
        let g3 = gz(b"zz");
        named.extend_from_slice(&g3[10..]);
        out.clear();
        assert!(gunzip(&named, &mut out, 1 << 30, None));
        assert_eq!(out, b"zz");
    }

    #[test]
    fn xz_ve_bz2() {
        let data = sample(300_000);
        let mut xz = Vec::new();
        {
            let mut e = liblzma::write::XzEncoder::new(&mut xz, 3);
            e.write_all(&data).unwrap();
            e.finish().unwrap();
        }
        let mut out = Vec::new();
        assert!(unxz(&xz, &mut out, 1 << 30));
        assert_eq!(out, data);
        out.clear();
        assert!(unxz(&xz, &mut out, 1024));
        assert_eq!(out, &data[..1024]);
        out.clear();
        assert!(unxz(&xz[..xz.len() / 2], &mut out, 1 << 30));
        assert!(!out.is_empty() && out.len() < data.len());
        assert_eq!(out, &data[..out.len()]);
        out.clear();
        assert!(!unxz(b"not xz data at all", &mut out, 1 << 30));

        let mut bz = Vec::new();
        {
            let mut e = bzip2::write::BzEncoder::new(&mut bz, bzip2::Compression::new(6));
            e.write_all(&data).unwrap();
            e.finish().unwrap();
        }
        out.clear();
        assert!(unbz2(&bz, &mut out, 1 << 30));
        assert_eq!(out, data);
        out.clear();
        assert!(unbz2(&bz, &mut out, 1024));
        assert_eq!(out, &data[..1024]);
        out.clear();
        assert!(unbz2(&bz[..bz.len() / 2], &mut out, 1 << 30));
        out.clear();
        assert!(!unbz2(b"BZh9garbage garbage garbage", &mut out, 1 << 30));
    }

    #[test]
    fn inflate_ham() {
        let data = sample(70_000);
        let c = deflate(&data);
        let mut out = Vec::new();
        let mut ended = false;
        assert!(inflate_raw(&c, &mut out, 1 << 30, Some(&mut ended)));
        assert_eq!(out, data);
        assert!(ended);
        out.clear();
        assert!(inflate_raw(&c[..c.len() / 2], &mut out, 1 << 30, Some(&mut ended)));
        assert!(!ended);
        out.clear();
        assert!(!inflate_raw(&[0xFF; 32], &mut out, 1 << 30, Some(&mut ended)));
        out.clear();
        assert!(inflate_raw(&c, &mut out, 100, Some(&mut ended)));
        assert_eq!(out.len(), 100);
    }

    #[test]
    fn lzma_yontem_14() {
        let data = sample(5000);
        let mut lz = Vec::new();
        {
            let opts = liblzma::stream::LzmaOptions::new_preset(3).unwrap();
            let stream = liblzma::stream::Stream::new_lzma_encoder(&opts).unwrap();
            let mut e = liblzma::write::XzEncoder::new_stream(&mut lz, stream);
            e.write_all(&data).unwrap();
            e.finish().unwrap();
        }
        assert!(lz.len() > 13);
        let mut zdata = vec![9, 20, 5, 0];
        zdata.extend_from_slice(&lz[..5]);
        zdata.extend_from_slice(&lz[13..]);
        let mut out = Vec::new();
        assert!(zip_lzma(&zdata, &mut out, 1 << 30));
        assert_eq!(out, data);
        out.clear();
        assert!(!zip_lzma(&[1, 2], &mut out, 100));
        assert!(!zip_lzma(&[0, 0, 9, 0, 1], &mut out, 100));
    }
}
