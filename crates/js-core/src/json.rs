use std::sync::Arc;

pub type JPtr = Arc<JVal>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JType {
    #[default]
    Nul,
    Bool,
    Int,
    Float,
    Str,
    Arr,
    Obj,
}

#[derive(Debug, Clone, Default)]
pub struct JVal {
    pub t: JType,
    pub b: bool,
    pub i: i64,
    pub d: f64,
    pub big: bool,
    pub s: String,
    pub arr: Vec<JPtr>,
    pub obj: Vec<(String, JPtr)>,
}

impl JVal {
    pub fn is_str(&self) -> bool {
        self.t == JType::Str
    }
    pub fn is_obj(&self) -> bool {
        self.t == JType::Obj
    }
    pub fn is_arr(&self) -> bool {
        self.t == JType::Arr
    }
    pub fn is_int(&self) -> bool {
        self.t == JType::Int
    }
    pub fn truthy(&self) -> bool {
        match self.t {
            JType::Nul => false,
            JType::Bool => self.b,
            JType::Int => self.big || self.i != 0,
            JType::Float => self.d != 0.0,
            JType::Str => !self.s.is_empty(),
            JType::Arr => !self.arr.is_empty(),
            JType::Obj => !self.obj.is_empty(),
        }
    }
    pub fn get(&self, k: &str) -> Option<&JVal> {
        if self.t != JType::Obj {
            return None;
        }
        self.obj.iter().find(|kv| kv.0 == k).map(|kv| &*kv.1)
    }
    pub fn py_str(&self) -> String {
        if self.t == JType::Str {
            self.s.clone()
        } else {
            self.py_repr()
        }
    }
    pub fn py_repr(&self) -> String {
        match self.t {
            JType::Nul => "None".to_string(),
            JType::Bool => (if self.b { "True" } else { "False" }).to_string(),
            JType::Int => {
                if self.big {
                    self.s.clone()
                } else {
                    self.i.to_string()
                }
            }
            JType::Float => float_repr(self.d),
            JType::Str => str_repr(&self.s),
            JType::Arr => {
                let mut o = String::from("[");
                for (k, x) in self.arr.iter().enumerate() {
                    if k > 0 {
                        o.push_str(", ");
                    }
                    o.push_str(&x.py_repr());
                }
                o.push(']');
                o
            }
            JType::Obj => {
                let mut o = String::from("{");
                for (k, (key, x)) in self.obj.iter().enumerate() {
                    if k > 0 {
                        o.push_str(", ");
                    }
                    o.push_str(&str_repr(key));
                    o.push_str(": ");
                    o.push_str(&x.py_repr());
                }
                o.push('}');
                o
            }
        }
    }
    pub fn str_or(&self, def: &str) -> String {
        if self.t == JType::Str {
            self.s.clone()
        } else {
            def.to_string()
        }
    }
}

fn fmt_g(d: f64, prec: usize) -> String {
    let e = format!("{:.*e}", prec - 1, d);
    let (mant, exp) = match e.split_once('e') {
        Some(x) => x,
        None => return e,
    };
    let x: i32 = exp.parse().unwrap_or(0);
    let strip = |s: &str| -> String {
        if s.contains('.') {
            s.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            s.to_string()
        }
    };
    if x < -4 || x >= prec as i32 {
        let m = strip(mant);
        let sign = if x < 0 { '-' } else { '+' };
        format!("{}e{}{:02}", m, sign, x.abs())
    } else {
        let decimals = (prec as i32 - 1 - x).max(0) as usize;
        strip(&format!("{:.*}", decimals, d))
    }
}

fn float_repr(d: f64) -> String {
    if d.is_nan() {
        return "nan".to_string();
    }
    if d.is_infinite() {
        return if d > 0.0 { "inf" } else { "-inf" }.to_string();
    }
    let mut s = String::new();
    for prec in 1..=17 {
        s = fmt_g(d, prec);
        if s.parse::<f64>().ok() == Some(d) {
            break;
        }
    }
    if !s.contains(['.', 'e', 'E', 'n']) {
        s.push_str(".0");
    }
    s
}

fn str_repr(s: &str) -> String {
    let sq = s.contains('\'') && !s.contains('"');
    let q = if sq { '"' } else { '\'' };
    let mut o = String::with_capacity(s.len() + 2);
    o.push(q);
    for c in s.chars() {
        if c == q || c == '\\' {
            o.push('\\');
            o.push(c);
        } else if c == '\n' {
            o.push_str("\\n");
        } else if c == '\r' {
            o.push_str("\\r");
        } else if c == '\t' {
            o.push_str("\\t");
        } else if (c as u32) < 0x20 || c as u32 == 0x7f {
            o.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            o.push(c);
        }
    }
    o.push(q);
    o
}

struct Parser<'a> {
    b: &'a [u8],
    p: usize,
    depth: i32,
    fail: bool,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.p).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.p += 1;
        }
    }
    fn lit(&mut self, s: &str) -> bool {
        if self.b.get(self.p..).is_some_and(|r| r.starts_with(s.as_bytes())) {
            self.p += s.len();
            true
        } else {
            false
        }
    }
    fn hexv(c: u8) -> Option<u32> {
        (c as char).to_digit(16)
    }
    fn u4(&mut self) -> Option<u32> {
        let r = self.b.get(self.p..self.p + 4)?;
        let mut v = 0u32;
        for &c in r {
            v = (v << 4) | Self::hexv(c)?;
        }
        self.p += 4;
        Some(v)
    }
    fn str_body(&mut self) -> Option<String> {
        let mut out: Vec<u8> = Vec::new();
        let push_cp = |out: &mut Vec<u8>, cp: u32| {
            let ch = char::from_u32(cp).unwrap_or('\u{FFFD}');
            let mut tmp = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
        };
        loop {
            let c = self.peek()?;
            if c == b'"' {
                self.p += 1;
                return String::from_utf8(out).ok();
            }
            if c < 0x20 {
                return None; // strict: kontrol karakteri yasak
            }
            if c == b'\\' {
                self.p += 1;
                let x = self.peek()?;
                self.p += 1;
                match x {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(8),
                    b'f' => out.push(12),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => {
                        let v = self.u4()?;
                        if (0xD800..=0xDBFF).contains(&v)
                            && self.b.len() - self.p >= 6
                            && self.b[self.p] == b'\\'
                            && self.b[self.p + 1] == b'u'
                        {
                            let save = self.p;
                            self.p += 2;
                            if let Some(v2) = self.u4() {
                                if (0xDC00..=0xDFFF).contains(&v2) {
                                    push_cp(&mut out, 0x10000 + ((v - 0xD800) << 10) + (v2 - 0xDC00));
                                    continue;
                                }
                            }
                            self.p = save;
                        }
                        push_cp(&mut out, v);
                    }
                    _ => return None,
                }
                continue;
            }
            out.push(c);
            self.p += 1;
        }
    }
    fn is_digit(&self, at: usize) -> bool {
        self.b.get(at).is_some_and(|c| c.is_ascii_digit())
    }
    fn value(&mut self) -> Option<JPtr> {
        self.depth += 1;
        if self.depth > 400 {
            self.fail = true;
            return None;
        }
        self.ws();
        let c = match self.peek() {
            Some(c) => c,
            None => {
                self.fail = true;
                return None;
            }
        };
        let mut v = JVal::default();
        if c == b'{' {
            self.p += 1;
            v.t = JType::Obj;
            self.ws();
            if self.peek() == Some(b'}') {
                self.p += 1;
                self.depth -= 1;
                return Some(Arc::new(v));
            }
            loop {
                self.ws();
                if self.peek() != Some(b'"') {
                    self.fail = true;
                    return None;
                }
                self.p += 1;
                let k = match self.str_body() {
                    Some(k) => k,
                    None => {
                        self.fail = true;
                        return None;
                    }
                };
                self.ws();
                if self.peek() != Some(b':') {
                    self.fail = true;
                    return None;
                }
                self.p += 1;
                let x = self.value();
                if self.fail {
                    return None;
                }
                let x = x?;
                if let Some(kv) = v.obj.iter_mut().find(|kv| kv.0 == k) {
                    kv.1 = x;
                } else {
                    v.obj.push((k, x));
                }
                self.ws();
                match self.peek() {
                    Some(b',') => {
                        self.p += 1;
                        continue;
                    }
                    Some(b'}') => {
                        self.p += 1;
                        break;
                    }
                    _ => {
                        self.fail = true;
                        return None;
                    }
                }
            }
        } else if c == b'[' {
            self.p += 1;
            v.t = JType::Arr;
            self.ws();
            if self.peek() == Some(b']') {
                self.p += 1;
                self.depth -= 1;
                return Some(Arc::new(v));
            }
            loop {
                let x = self.value();
                if self.fail {
                    return None;
                }
                v.arr.push(x?);
                self.ws();
                match self.peek() {
                    Some(b',') => {
                        self.p += 1;
                        continue;
                    }
                    Some(b']') => {
                        self.p += 1;
                        break;
                    }
                    _ => {
                        self.fail = true;
                        return None;
                    }
                }
            }
        } else if c == b'"' {
            self.p += 1;
            v.t = JType::Str;
            match self.str_body() {
                Some(s) => v.s = s,
                None => {
                    self.fail = true;
                    return None;
                }
            }
        } else if self.lit("null") {
            v.t = JType::Nul;
        } else if self.lit("true") {
            v.t = JType::Bool;
            v.b = true;
        } else if self.lit("false") {
            v.t = JType::Bool;
            v.b = false;
        } else if self.lit("NaN") {
            v.t = JType::Float;
            v.d = f64::NAN;
        } else if self.lit("Infinity") {
            v.t = JType::Float;
            v.d = f64::INFINITY;
        } else if self.lit("-Infinity") {
            v.t = JType::Float;
            v.d = f64::NEG_INFINITY;
        } else if c == b'-' || c.is_ascii_digit() {
            let s0 = self.p;
            if self.peek() == Some(b'-') {
                self.p += 1;
            }
            if !self.is_digit(self.p) {
                self.fail = true;
                return None;
            }
            if self.peek() == Some(b'0') {
                self.p += 1;
            } else {
                while self.is_digit(self.p) {
                    self.p += 1;
                }
            }
            let mut isf = false;
            if self.peek() == Some(b'.') && self.is_digit(self.p + 1) {
                isf = true;
                self.p += 1;
                while self.is_digit(self.p) {
                    self.p += 1;
                }
            }
            if matches!(self.peek(), Some(b'e' | b'E')) {
                let mut q = self.p + 1;
                if matches!(self.b.get(q), Some(b'+' | b'-')) {
                    q += 1;
                }
                if self.is_digit(q) {
                    isf = true;
                    self.p = q;
                    while self.is_digit(self.p) {
                        self.p += 1;
                    }
                }
            }
            let num = std::str::from_utf8(&self.b[s0..self.p]).unwrap_or("0");
            if isf {
                v.t = JType::Float;
                v.d = num.parse::<f64>().unwrap_or(0.0);
            } else {
                v.t = JType::Int;
                match num.parse::<i64>() {
                    Ok(x) => v.i = x,
                    Err(_) => {
                        v.big = true;
                        v.s = num.to_string();
                        v.i = if num.starts_with('-') { i64::MIN } else { i64::MAX };
                    }
                }
            }
        } else {
            self.fail = true;
            return None;
        }
        self.depth -= 1;
        Some(Arc::new(v))
    }
}

pub fn json_parse(text: &str) -> Option<JPtr> {
    let b = text.as_bytes();
    if b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return None;
    }
    let mut ps = Parser {
        b,
        p: 0,
        depth: 0,
        fail: false,
    };
    let v = ps.value();
    if ps.fail {
        return None;
    }
    let v = v?;
    ps.ws();
    if ps.p != b.len() {
        return None;
    }
    Some(v)
}

fn utf8_decode_ignore(b: &[u8]) -> String {
    let mut o = String::with_capacity(b.len());
    let mut rest = b;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                o.push_str(s);
                break;
            }
            Err(e) => {
                let (ok, bad) = rest.split_at(e.valid_up_to());
                if let Ok(s) = std::str::from_utf8(ok) {
                    o.push_str(s);
                }
                rest = bad.get(1..).unwrap_or(&[]);
            }
        }
    }
    o
}

pub fn read_json_bytes(data: &[u8]) -> Option<JPtr> {
    let txt = utf8_decode_ignore(data);
    let tb = txt.as_bytes();
    let n = tb.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0usize;
    while i <= n {
        let j = tb[i..].iter().position(|&c| c == b'\n').map_or(n, |x| i + x);
        let line = &tb[i..j];
        let mut k = 0;
        while k < line.len() && matches!(line[k], b' ' | b'\t' | b'\r' | 0x0b | 0x0c) {
            k += 1;
        }
        if !(k + 1 < line.len() && line[k] == b'/' && line[k + 1] == b'/') {
            out.extend_from_slice(line);
        }
        if j < n {
            out.push(b'\n');
        }
        i = j + 1;
        if j == n {
            break;
        }
    }
    let s = String::from_utf8(out).ok()?;
    json_parse(&s)
}

pub fn load_json_file(path: &str) -> Option<JPtr> {
    let d = std::fs::read(path).ok()?;
    let s = std::str::from_utf8(&d).ok()?;
    json_parse(s)
}

pub fn jget<'a>(v: Option<&'a JVal>, k: &str) -> Option<&'a JVal> {
    v.and_then(|v| v.get(k))
}
pub fn jstr(v: Option<&JVal>) -> String {
    match v {
        Some(v) if v.t == JType::Str => v.s.clone(),
        _ => String::new(),
    }
}
pub fn jtruthy(v: Option<&JVal>) -> bool {
    v.is_some_and(|v| v.truthy())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> JPtr {
        json_parse(s).expect("parse")
    }

    #[test]
    fn temel_degerler() {
        assert_eq!(p("null").t, JType::Nul);
        assert!(p("true").b);
        assert_eq!(p("-12").i, -12);
        assert_eq!(p("1.5").d, 1.5);
        assert_eq!(p("1e2").d, 100.0);
        assert_eq!(p("\"a\\n\\u00e9\"").s, "a\né");
        assert_eq!(p("\"\\ud83d\\ude00\"").s, "😀");
        assert!(p("NaN").d.is_nan());
        assert_eq!(p("-Infinity").d, f64::NEG_INFINITY);
    }

    #[test]
    fn buyuk_tamsayi() {
        let v = p("123456789012345678901234567890");
        assert!(v.big);
        assert_eq!(v.py_repr(), "123456789012345678901234567890");
        assert!(v.truthy());
        let n = p("-99999999999999999999");
        assert_eq!(n.i, i64::MIN);
        assert!(n.big);
    }

    #[test]
    fn hatalar() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "1.",
            "\"a\nb\"",
            "tru",
            "{'a':1}",
            "[1] x",
            "\"\\x\"",
            "-",
            "\u{feff}1",
            "\"\\u12\"",
        ] {
            assert!(json_parse(bad).is_none(), "{bad:?}");
        }
        assert!(json_parse("1 ").is_some());
    }

    #[test]
    fn derinlik_siniri() {
        let ok = format!("{}{}", "[".repeat(399), "]".repeat(399));
        assert!(json_parse(&ok).is_some());
        let bad = format!("{}{}", "[".repeat(401), "]".repeat(401));
        assert!(json_parse(&bad).is_none());
    }

    #[test]
    fn sira_ve_tekrar_anahtar() {
        let v = p("{\"b\":1,\"a\":2,\"b\":3}");
        let keys: Vec<&str> = v.obj.iter().map(|kv| kv.0.as_str()).collect();
        assert_eq!(keys, ["b", "a"]);
        assert_eq!(v.get("b").map(|x| x.i), Some(3));
        assert!(v.get("zz").is_none());
        assert!(jget(Some(&v), "a").is_some());
        assert!(!jtruthy(None));
    }

    #[test]
    fn py_repr_str() {
        let v = p("{\"k\": [1, 2.0, \"it's\", \"q\\\"\", null, true, \"\\u0001\\t\", 1e16, 0.1, 100000.0]}");
        assert_eq!(
            v.py_repr(),
            "{'k': [1, 2.0, \"it's\", 'q\"', None, True, '\\x01\\t', 1e+16, 0.1, 1e+05]}"
        );
        assert_eq!(p("\"x'\\\"\"").py_repr(), "'x\\'\"'");
        assert_eq!(p("\"abc\"").py_str(), "abc");
        assert_eq!(p("[]").py_str(), "[]");
        assert_eq!(p("{}").py_repr(), "{}");
        assert_eq!(p("-0.0").py_repr(), "-0.0");
        assert_eq!(p("1e-5").py_repr(), "1e-05");
        assert_eq!(p("123.456").py_repr(), "123.456");
        assert_eq!(p("Infinity").py_repr(), "inf");
        assert_eq!(p("NaN").py_repr(), "nan");
    }

    #[test]
    fn truthy_ve_yardimcilar() {
        assert!(!p("0").truthy());
        assert!(!p("0.0").truthy());
        assert!(!p("\"\"").truthy());
        assert!(!p("[]").truthy());
        assert!(p("[0]").truthy());
        assert_eq!(jstr(Some(&p("\"x\""))), "x");
        assert_eq!(jstr(Some(&p("1"))), "");
        assert_eq!(p("1").str_or("d"), "d");
    }

    #[test]
    fn yorum_satirlari_ve_gecersiz_utf8() {
        let src = b"{\n  // yorum\n  \"a\": 1,\n\t// baska\n  \"b\": \"x\xffy\"\n}";
        let v = read_json_bytes(src).expect("parse");
        assert_eq!(v.get("a").map(|x| x.i), Some(1));
        assert_eq!(v.get("b").map(|x| x.s.as_str()), Some("xy"));
        let v = read_json_bytes(b"{\"u\": \"http://x\"}").expect("parse");
        assert_eq!(v.get("u").map(|x| x.s.as_str()), Some("http://x"));
        assert!(read_json_bytes(b"{").is_none());
    }

    #[test]
    fn yalniz_vekil() {
        assert_eq!(p("\"\\ud800x\"").s, "\u{FFFD}x");
        assert_eq!(p("\"\\ud800\\u0041\"").s, "\u{FFFD}A");
    }
}
