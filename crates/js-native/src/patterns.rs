use crate::pat_data::*;
use crate::util::*;
use std::sync::OnceLock;

pub const SCANNER_MARKER: &str = "AVENOR-SCANNER-SIGDB-9c4f1e7a";

#[derive(Default)]
pub struct AhoCorasick {
    nodes: usize,
    go: Vec<i32>,
    fail: Vec<i32>,
    outs: Vec<Vec<i32>>,
}

impl AhoCorasick {
    fn new_node(&mut self) -> usize {
        self.go.resize(self.go.len() + 256, -1);
        self.fail.push(0);
        self.outs.push(Vec::new());
        self.nodes += 1;
        self.nodes - 1
    }
    pub fn add(&mut self, pat: &[u8], id: i32) {
        if self.nodes == 0 {
            self.new_node();
        }
        let mut s = 0usize;
        for &c in pat {
            let nx = self.go[s * 256 + c as usize];
            if nx == -1 {
                let nn = self.new_node();
                self.go[s * 256 + c as usize] = nn as i32;
                s = nn;
            } else {
                s = nx as usize;
            }
        }
        self.outs[s].push(id);
    }
    pub fn build(&mut self) {
        if self.nodes == 0 {
            self.new_node();
        }
        let mut q: Vec<usize> = Vec::new();
        for c in 0..256 {
            let v = self.go[c];
            if v == -1 {
                self.go[c] = 0;
            } else {
                self.fail[v as usize] = 0;
                q.push(v as usize);
            }
        }
        let mut qi = 0;
        while qi < q.len() {
            let u = q[qi];
            qi += 1;
            for c in 0..256 {
                let v = self.go[u * 256 + c];
                let fu = self.fail[u] as usize;
                if v == -1 {
                    self.go[u * 256 + c] = self.go[fu * 256 + c];
                } else {
                    let v = v as usize;
                    let f = self.go[fu * 256 + c];
                    self.fail[v] = f;
                    let extra = self.outs[f as usize].clone();
                    self.outs[v].extend(extra);
                    q.push(v);
                }
            }
        }
    }
    pub fn search<F: FnMut(i32, usize)>(&self, t: &[u8], mut cb: F) {
        if self.nodes == 0 {
            return;
        }
        let mut s = 0usize;
        for (i, &c) in t.iter().enumerate() {
            s = self.go[s * 256 + c as usize] as usize;
            let o = &self.outs[s];
            if !o.is_empty() {
                for &id in o {
                    cb(id, i + 1);
                }
            }
        }
    }
}

pub struct PatInfo {
    pub text: Vec<u8>,
    pub cat: u8,
    pub flags: u8,
    pub w: u8,
    pub label: &'static str,
}

pub struct PatDb {
    pub pats: Vec<PatInfo>,
    pub raw: AhoCorasick,
    pub norm: AhoCorasick,
}

impl PatDb {
    fn new() -> PatDb {
        let mut db = PatDb {
            pats: Vec::new(),
            raw: AhoCorasick::default(),
            norm: AhoCorasick::default(),
        };
        for (i, d) in PAT_DEFS.iter().enumerate() {
            let mut t: Vec<u8> = d.text.bytes().map(low_c).collect();
            if d.flags & F_NORM != 0 {
                t.retain(|&c| c != b' ' && c != b'_' && c != b'-');
            }
            if d.flags & F_NORM != 0 {
                db.norm.add(&t, i as i32);
            } else {
                db.raw.add(&t, i as i32);
            }
            db.pats.push(PatInfo {
                text: t,
                cat: d.cat,
                flags: d.flags,
                w: d.w,
                label: d.label,
            });
        }
        db.raw.build();
        db.norm.build();
        db
    }
}

pub fn get_db() -> &'static PatDb {
    static DB: OnceLock<PatDb> = OnceLock::new();
    DB.get_or_init(PatDb::new)
}

pub fn extract_strings<F: FnMut(&[u8], usize, bool)>(p: &[u8], from: usize, to: usize, min_len: usize, mut cb: F) {
    const MAX_RUN: usize = 4096;
    let n = p.len();
    let to = to.min(n);
    {
        let mut i = from;
        if from > 0 && from < n && is_print_a(p[from - 1]) && is_print_a(p[from]) {
            while i < n && is_print_a(p[i]) {
                i += 1;
            }
        }
        while i < to {
            if !is_print_a(p[i]) {
                i += 1;
                continue;
            }
            let st = i;
            while i < n && is_print_a(p[i]) && i - st < MAX_RUN {
                i += 1;
            }
            let len = i - st;
            if len >= min_len {
                cb(&p[st..st + len], st, false);
            }
            while i < n && is_print_a(p[i]) {
                i += 1;
            }
        }
    }
    {
        let mut i = (from + 1) & !1usize;
        if i >= 2 && i < n && is_print_a(p[i - 2]) && p[i - 1] == 0 && i + 1 < n && is_print_a(p[i]) && p[i + 1] == 0 {
            while i + 1 < n && is_print_a(p[i]) && p[i + 1] == 0 {
                i += 2;
            }
        }
        let mut tmp: Vec<u8> = Vec::new();
        while i + 1 < to {
            if is_print_a(p[i]) && p[i + 1] == 0 {
                let st = i;
                tmp.clear();
                while i + 1 < n && is_print_a(p[i]) && p[i + 1] == 0 && tmp.len() < MAX_RUN {
                    tmp.push(p[i]);
                    i += 2;
                }
                if tmp.len() >= min_len {
                    cb(&tmp, st, true);
                }
                while i + 1 < n && is_print_a(p[i]) && p[i + 1] == 0 {
                    i += 2;
                }
            } else {
                i += 2;
            }
        }
    }
}

pub fn boundary_ok(s: &[u8], st: usize, en: usize) -> bool {
    let n = s.len();
    if st > 0 && is_alnum(s[st - 1]) {
        return false;
    }
    if en < n {
        let a = s[en - 1];
        let b = s[en];
        if is_alnum(b) {
            let camel = is_upper(b) && (is_lower(a) || is_dig(a));
            if !camel && !is_dig(b) {
                return false;
            }
        }
    }
    true
}

#[derive(Default)]
pub struct StrCtx {
    pub low: Vec<u8>,
    pub norm: Vec<u8>,
    pub map: Vec<u32>,
}

pub fn match_string<F: FnMut(i32, usize, usize)>(s: &[u8], cx: &mut StrCtx, heap_only: bool, mut cb: F) {
    let db = get_db();
    let n = s.len();
    cx.low.clear();
    let mut sep = false;
    for &b in s {
        let c = low_c(b);
        cx.low.push(c);
        if c == b' ' || c == b'_' || c == b'-' {
            sep = true;
        }
    }
    db.raw.search(&cx.low, |id, en| {
        let pi = &db.pats[id as usize];
        if heap_only && pi.flags & F_HEAP == 0 {
            return;
        }
        let st = en - pi.text.len();
        if pi.flags & F_BOUND != 0 && !boundary_ok(s, st, en) {
            return;
        }
        cb(id, st, en);
    });
    if sep {
        cx.norm.clear();
        cx.map.clear();
        for i in 0..n {
            let c = cx.low[i];
            if c == b' ' || c == b'_' || c == b'-' {
                continue;
            }
            cx.norm.push(c);
            cx.map.push(i as u32);
        }
    }
    let StrCtx { low, norm, map } = cx;
    let nt: &[u8] = if sep { norm } else { low };
    db.norm.search(nt, |id, en| {
        let pi = &db.pats[id as usize];
        if heap_only && pi.flags & F_HEAP == 0 {
            return;
        }
        let st = en - pi.text.len();
        let (mut os, mut oe) = (st, en);
        if sep {
            os = map[st] as usize;
            oe = map[en - 1] as usize + 1;
        }
        let crossed = (oe - os) != pi.text.len(); // eşleşme boşluk/_/- üzerinden birden fazla kelimeyi kapsıyor -> sınırlar ZORUNLU
        if (crossed || pi.flags & F_BOUND != 0) && !boundary_ok(s, os, oe) {
            return;
        }
        cb(id, os, oe);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(s: &str, heap: bool) -> Vec<String> {
        let mut cx = StrCtx::default();
        let mut v = Vec::new();
        match_string(s.as_bytes(), &mut cx, heap, |id, _, _| {
            v.push(get_db().pats[id as usize].label.to_string())
        });
        v
    }
    #[test]
    fn killaura_norm() {
        assert!(matches("Kill Aura", false).contains(&"KillAura".to_string()));
        assert!(matches("KillAuraModule", false).contains(&"KillAura".to_string()));
    }
    #[test]
    fn boundary_left_strict() {
        assert!(!matches("GuardLongJumpTargetTable", false).contains(&"LongJump".to_string()));
        assert!(matches("PKEY_Author", false)
            .iter()
            .all(|l| l != "KeyAuth lisans sistemi"));
    }
    #[test]
    fn extract_ascii_and_wide() {
        let mut got = Vec::new();
        let mut buf = b"\x01\x01hello world\x01\x01\x01".to_vec();
        buf.extend_from_slice(b"w\0i\0d\0e\0s\0t\0r\0\0\0");
        extract_strings(&buf, 0, buf.len(), 5, |s, st, w| {
            got.push((String::from_utf8_lossy(s).to_string(), st, w))
        });
        assert!(got.iter().any(|(s, _, w)| s == "hello world" && !*w));
        assert!(got.iter().any(|(s, _, w)| s == "widestr" && *w));
    }
    #[test]
    fn heap_filter() {
        assert!(matches("cmd /c", true).is_empty());
        assert!(!matches("cmd /c", false).is_empty());
    }
}
