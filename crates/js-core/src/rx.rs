use regex_automata::meta;
use regex_automata::util::syntax;
use regex_automata::{Anchored, Input};

#[derive(Debug, Clone, Default)]
pub struct RxMatch<'a> {
    pub subj: &'a [u8],
    pub ov: Vec<i64>,
}
impl<'a> RxMatch<'a> {
    pub fn ok(&self, g: usize) -> bool {
        match self.ov.get(2 * g) {
            Some(&s) => self.ov.len() > 2 * g + 1 && s >= 0,
            None => false,
        }
    }
    pub fn group(&self, g: usize) -> String {
        String::from_utf8_lossy(self.group_bytes(g)).into_owned()
    }
    pub fn group_bytes(&self, g: usize) -> &'a [u8] {
        if !self.ok(g) {
            return &[];
        }
        let (s, e) = (self.ov[2 * g] as usize, self.ov[2 * g + 1] as usize);
        self.subj.get(s..e).unwrap_or(&[])
    }
    pub fn start(&self, g: usize) -> usize {
        if self.ok(g) {
            self.ov[2 * g] as usize
        } else {
            0
        }
    }
    pub fn end(&self, g: usize) -> usize {
        if self.ok(g) {
            self.ov[2 * g + 1] as usize
        } else {
            0
        }
    }
}

pub const RX_I: i32 = 1;
pub const RX_M: i32 = 2;
pub const RX_S: i32 = 4;
pub const RX_BYTES: i32 = 8;

struct Plain {
    re: meta::Regex,
    full: meta::Regex,
}

struct Fancy {
    re: fancy_regex::Regex,
    full: fancy_regex::Regex,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Search,
    Anchored,
    Full,
}

pub struct Rx {
    flags: i32,
    plain: Option<Plain>,
    fancy: Option<Fancy>,
}

fn rewrite_dollar(p: &str) -> Option<String> {
    let mut out = String::with_capacity(p.len() + 8);
    let mut in_class = false;
    let mut changed = false;
    let mut it = p.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                out.push(c);
                if let Some(n) = it.next() {
                    out.push(n);
                }
            }
            '[' if !in_class => {
                in_class = true;
                out.push(c);
                if let Some(n) = it.next_if_eq(&'^') {
                    out.push(n);
                }
                if let Some(n) = it.next_if_eq(&']') {
                    out.push(n);
                }
            }
            '[' if in_class => {
                out.push(c);
                if it.peek() == Some(&':') {
                    let mut prev = '\0';
                    for n in it.by_ref() {
                        out.push(n);
                        if prev == ':' && n == ']' {
                            break;
                        }
                        prev = n;
                    }
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            '$' if !in_class => {
                out.push_str("(?=\\n?\\z)");
                changed = true;
            }
            _ => out.push(c),
        }
    }
    changed.then_some(out)
}

fn flag_prefix(flags: i32) -> String {
    let mut f = String::new();
    if flags & RX_I != 0 {
        f.push('i');
    }
    if flags & RX_M != 0 {
        f.push('m');
    }
    if flags & RX_S != 0 {
        f.push('s');
    }
    if f.is_empty() {
        String::new()
    } else {
        format!("(?{f})")
    }
}

fn build_plain(pattern: &str, flags: i32) -> Option<Plain> {
    let syn = syntax::Config::new()
        .case_insensitive(flags & RX_I != 0)
        .multi_line(flags & RX_M != 0)
        .dot_matches_new_line(flags & RX_S != 0)
        .unicode(flags & RX_BYTES == 0)
        .utf8(false);
    let cfg = meta::Config::new().utf8_empty(false);
    let build = |p: &str| meta::Builder::new().configure(cfg.clone()).syntax(syn).build(p).ok();
    let re = build(pattern)?;
    let full = build(&format!("(?:{pattern})\\z"))?;
    Some(Plain { re, full })
}

fn build_fancy(pattern: &str, flags: i32) -> Result<Fancy, String> {
    let fp = flag_prefix(flags);
    let re = fancy_regex::Regex::new(&format!("{fp}(?:{pattern})")).map_err(|e| e.to_string())?;
    let full = fancy_regex::Regex::new(&format!("{fp}(?:{pattern})\\z")).map_err(|e| e.to_string())?;
    Ok(Fancy { re, full })
}

struct FancySubj<'s> {
    text: std::borrow::Cow<'s, str>,
    bounds: Option<Vec<(usize, usize)>>,
}

impl<'s> FancySubj<'s> {
    fn new(s: &'s [u8], bytes_mode: bool) -> FancySubj<'s> {
        if !bytes_mode {
            if let Ok(t) = std::str::from_utf8(s) {
                return FancySubj {
                    text: t.into(),
                    bounds: None,
                };
            }
        } else if s.is_ascii() {
            return FancySubj {
                text: String::from_utf8_lossy(s),
                bounds: None,
            };
        }
        let mut text = String::with_capacity(s.len() + 8);
        let mut bounds: Vec<(usize, usize)> = Vec::with_capacity(s.len() + 1);
        if bytes_mode {
            for (i, &b) in s.iter().enumerate() {
                bounds.push((text.len(), i));
                text.push(b as char);
            }
        } else {
            let mut pos = 0usize;
            while pos < s.len() {
                let rest = &s[pos..];
                let (valid, bad) = match std::str::from_utf8(rest) {
                    Ok(t) => (t, 0),
                    Err(e) => {
                        let n = e.valid_up_to();
                        (std::str::from_utf8(&rest[..n]).unwrap_or(""), 1)
                    }
                };
                for (off, ch) in valid.char_indices() {
                    bounds.push((text.len(), pos + off));
                    text.push(ch);
                }
                pos += valid.len();
                if bad > 0 && pos < s.len() {
                    bounds.push((text.len(), pos));
                    text.push('\u{FFFD}');
                    pos += 1;
                }
            }
        }
        bounds.push((text.len(), s.len()));
        FancySubj {
            text: text.into(),
            bounds: Some(bounds),
        }
    }
    fn to_conv(&self, orig: usize) -> Option<usize> {
        match &self.bounds {
            None => (orig <= self.text.len() && self.text.is_char_boundary(orig)).then_some(orig),
            Some(b) => b.binary_search_by_key(&orig, |x| x.1).ok().map(|i| b[i].0),
        }
    }
    fn to_orig(&self, conv: usize) -> usize {
        match &self.bounds {
            None => conv,
            Some(b) => match b.binary_search_by_key(&conv, |x| x.0) {
                Ok(i) => b[i].1,
                Err(i) => b.get(i).map_or(0, |x| x.1),
            },
        }
    }
}

impl Rx {
    pub const I: i32 = RX_I;
    pub const M: i32 = RX_M;
    pub const S: i32 = RX_S;
    pub const BYTES: i32 = RX_BYTES;

    pub fn new(pattern: &str, flags: i32) -> Rx {
        let dollar = if flags & RX_M == 0 {
            rewrite_dollar(pattern)
        } else {
            None
        };
        let mut rx = Rx {
            flags,
            plain: None,
            fancy: None,
        };
        if let Some(p) = build_plain(pattern, flags) {
            rx.plain = Some(p);
            if let Some(dp) = dollar {
                rx.fancy = build_fancy(&dp, flags).ok();
            }
            return rx;
        }
        let src = dollar.as_deref().unwrap_or(pattern);
        match build_fancy(src, flags) {
            Ok(f) => rx.fancy = Some(f),
            Err(e) => eprintln!("regex derlenemedi: {} ({})", pattern, e),
        }
        rx
    }

    fn exec<'a>(&self, s: &'a [u8], start: usize, mode: Mode) -> Option<RxMatch<'a>> {
        if start > s.len() {
            return None;
        }
        let use_fancy = match (&self.plain, &self.fancy) {
            (Some(_), Some(_)) => s.last() == Some(&b'\n'),
            (None, Some(_)) => true,
            _ => false,
        };
        if use_fancy {
            self.exec_fancy(s, start, mode)
        } else {
            self.exec_plain(s, start, mode)
        }
    }

    fn exec_plain<'a>(&self, s: &'a [u8], start: usize, mode: Mode) -> Option<RxMatch<'a>> {
        let p = self.plain.as_ref()?;
        let re = if mode == Mode::Full { &p.full } else { &p.re };
        let anchored = if mode == Mode::Search {
            Anchored::No
        } else {
            Anchored::Yes
        };
        let input = Input::new(s).span(start..s.len()).anchored(anchored);
        let mut caps = re.create_captures();
        re.search_captures(&input, &mut caps);
        if !caps.is_match() {
            return None;
        }
        let n = caps.group_len();
        let mut ov = vec![-1i64; 2 * n];
        for i in 0..n {
            if let Some(sp) = caps.get_group(i) {
                ov[2 * i] = sp.start as i64;
                ov[2 * i + 1] = sp.end as i64;
            }
        }
        Some(RxMatch { subj: s, ov })
    }

    fn exec_fancy<'a>(&self, s: &'a [u8], start: usize, mode: Mode) -> Option<RxMatch<'a>> {
        let f = self.fancy.as_ref()?;
        let subj = FancySubj::new(s, self.flags & RX_BYTES != 0);
        let cstart = subj.to_conv(start)?;
        let re = if mode == Mode::Full { &f.full } else { &f.re };
        let caps = re.captures_from_pos(&subj.text, cstart).ok()??;
        let m0 = caps.get(0)?;
        if mode != Mode::Search && m0.start() != cstart {
            return None;
        }
        let n = re.captures_len();
        let mut ov = vec![-1i64; 2 * n];
        for i in 0..n {
            if let Some(m) = caps.get(i) {
                ov[2 * i] = subj.to_orig(m.start()) as i64;
                ov[2 * i + 1] = subj.to_orig(m.end()) as i64;
            }
        }
        Some(RxMatch { subj: s, ov })
    }

    pub fn search<'a>(&self, s: &'a [u8], start: usize) -> Option<RxMatch<'a>> {
        self.exec(s, start, Mode::Search)
    }
    pub fn match_<'a>(&self, s: &'a [u8], start: usize) -> Option<RxMatch<'a>> {
        self.exec(s, start, Mode::Anchored)
    }
    pub fn fullmatch<'a>(&self, s: &'a [u8]) -> Option<RxMatch<'a>> {
        self.exec(s, 0, Mode::Full)
    }
    pub fn finditer<'a>(&self, s: &'a [u8], cb: &mut dyn FnMut(&RxMatch<'a>) -> bool) {
        let mut pos = 0usize;
        while pos <= s.len() {
            let m = match self.exec(s, pos, Mode::Search) {
                Some(m) => m,
                None => break,
            };
            if !cb(&m) {
                break;
            }
            let mut e = m.end(0);
            if e == m.start(0) {
                e += 1;
                if self.flags & RX_BYTES == 0 {
                    while e < s.len() && (s[e] & 0xC0) == 0x80 {
                        e += 1;
                    }
                }
            }
            pos = e;
        }
    }
    pub fn findall<'a>(&self, s: &'a [u8]) -> Vec<RxMatch<'a>> {
        let mut out = Vec::new();
        self.finditer(s, &mut |m| {
            out.push(m.clone());
            true
        });
        out
    }
    pub fn valid(&self) -> bool {
        self.plain.is_some() || self.fancy.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rx(p: &str, f: i32) -> Rx {
        let r = Rx::new(p, f);
        assert!(r.valid(), "derlenemedi: {p}");
        r
    }

    fn all_patterns() -> Vec<(&'static str, i32)> {
        vec![
            ("accesstoken|access_token|sessionid", 0),
            (r"(^|[\\/])javaw?(\.exe)?$", RX_I),
            (r"(^|[\\/])(java|javaw)(\.exe)?$", RX_I),
            ("VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", 0),
            ("DEV_([0-9A-Fa-f]{12})", RX_I),
            (r"BTHENUM\\\{([0-9A-F]{8})-", 0),
            (r"[&_]([0-9A-F]{12})(?:_|$)", 0),
            (r"\\fsquirt\.exe$", RX_I),
            ("-javaagent:\\s*\"?([^\"\\r\\n]+?\\.jar)", RX_I),
            ("(?:fabric|loader)\\.addMods\\s*=\\s*\"?([^\"\\r\\n ]+)", RX_I),
            ("\"([^\"\\r\\n]+?\\.jar)\"|([^\\s\"';=<>|*?]+\\.jar)\\b", RX_I),
            ("modId\\s*=\\s*\"([^\"]+)\"", 0),
            ("displayName\\s*=\\s*\"([^\"]+)\"", 0),
            ("version\\s*=\\s*\"([^\"]+)\"", 0),
            ("clientSideOnly\\s*=\\s*true", 0),
            ("displayTest\\s*=\\s*\"IGNORE_(ALL|SERVER)_VERSION\"", 0),
            ("\"id\"\\s*:\\s*\"([^\"]+)\"", RX_BYTES),
            ("^(Premain-Class|Agent-Class|Launcher-Agent-Class)\\s*:\\s*(\\S+)", RX_M),
            ("^Main-Class\\s*:\\s*([A-Za-z0-9_.$]+)", RX_M),
            ("via(version|backwards|rewind|legacy|loader)", 0),
            ("^\\s*package\\s+([A-Za-z_][\\w.]*)\\s*;?", RX_M | RX_BYTES),
            ("^(module|hack|feature|function|cheat)(?=[a-z]{3})", 0),
            ("(module|hack|feature|function|cheat|mod|impl)$", 0),
            ("^main\\s*:\\s*['\"]?([A-Za-z0-9_.$]+)", RX_M),
            ("\"main\"\\s*:\\s*\"([A-Za-z0-9_.$]+)\"", 0),
            (
                r"^\[(\d{2}:\d{2}:\d{2})\]|^\[(\d{2}[A-Za-z]{3}\d{4} \d{2}:\d{2}:\d{2}\.\d+)\]|^\[\d",
                0,
            ),
            (
                r"^\[[^\]]+\] \[main/(?:INFO|DEBUG)\](?: \([^)]*\))?:? (?:\[FabricLoader\] |\[QuiltLoader\] )?Loading (\d+) mods?:\s*(.*)$",
                0,
            ),
            (
                r"^[\t ]*(?:\|[\t ]+)*(?:-|\|--|\\--)[\t ]+([A-Za-z0-9_.\-]+)[\t ]+(\S+)",
                0,
            ),
            (r"([A-Za-z0-9_.\-]+)@(\S+?)(?:,|$)", 0),
            (
                r"Found valid mod file (.+?) with \{([^}]*)\} mods - versions \{([^}]*)\}",
                0,
            ),
            (r"Considering mod file candidate (.+\.jar)\s*$", RX_I),
            (
                r"Found mod file (.+?) of type (\w+) with provider \{?mods folder locator at (.+?)\}?\s*$",
                0,
            ),
            (
                r"^\s+(\S.*?\.jar)\s*\|([^|]*)\|\s*([A-Za-z0-9_.\-]+)\s*\|\s*([^|]+?)\s*\|",
                0,
            ),
            (r"^\s*(?:-- )?Mod List(?: --)?:?\s*$|^\s*Mod List:\s*$", 0),
            (r"Loading Minecraft (\S+) with (Fabric Loader|Quilt Loader) (\S+)", 0),
            (
                r"(?:Forge|NeoForge) (?:mod loader )?version (\S+)|--fml\.(?:forge|neoForge)Version, (\S+?)[,\]]",
                0,
            ),
            (
                r"--fml\.mcVersion, (\S+?)[,\]]|Minecraft Version: (\S+)|Loading Minecraft (\S+)",
                0,
            ),
            (r"Setting user: (\S+)|--username, (\S+?)[,\]]", 0),
            (r"Connecting to ([^,\s]+), ?(\d+)", 0),
            (
                r"Starting integrated minecraft server version|Preparing start region for dimension",
                0,
            ),
            (r"(\d{4})-(\d{2})-(\d{2})", 0),
            (r"^Implementation-Version:\s*(\S+)", RX_M),
            (r#"modId\s*=\s*"([^"]+)""#, 0),
            (r#"version\s*=\s*"([^"]+)""#, 0),
            (r"^\\VOLUME\{[0-9a-fA-F]+-([0-9a-fA-F]+)\}", RX_I),
            (r"^(\\DEVICE\\HARDDISKVOLUME\d+)", RX_I),
            (r"\d{4}-\d{2}-\d{2}", 0),
        ]
    }

    #[test]
    fn tum_desenler_derlenir() {
        for (p, f) in all_patterns() {
            let r = Rx::new(p, f);
            assert!(r.valid(), "derlenemedi: {p}");
        }
        assert!(all_patterns().len() >= 47);
    }

    #[test]
    fn dolar_son_satir_sonu() {
        let r = rx(r"(^|[\\/])javaw?(\.exe)?$", RX_I);
        let m = r.search(b"C:\\x\\JAVAW.exe\n", 0).expect("eşleşme");
        assert_eq!(m.group(0), "\\JAVAW.exe");
        assert!(r.search(b"C:\\x\\javaw.exe", 0).is_some());
        assert!(r.search(b"C:\\x\\javaw.exe\n\n", 0).is_none());
        assert!(r.search(b"C:\\x\\javaw.exe2", 0).is_none());
        let r = rx("^a$", RX_M);
        assert_eq!(r.findall(b"a\na\nb").len(), 2);
        let r = rx(r"[&_]([0-9A-F]{12})(?:_|$)", 0);
        let m = r.search(b"x&0123456789AB\n", 0).expect("eşleşme");
        assert_eq!(m.group(1), "0123456789AB");
        assert_eq!(m.end(0), 14);
    }

    #[test]
    fn grup_ve_bayrak() {
        let r = rx("VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", 0);
        let m = r.search(b"USB\\VID_046D&PID_C52B\\x", 0).expect("eşleşme");
        assert_eq!(m.group(1), "046D");
        assert_eq!(m.group(2), "C52B");
        assert_eq!(m.start(0), 4);
        assert!(!m.ok(3));
        assert_eq!(m.group(3), "");
        let r = rx("dev_([0-9a-f]{12})", RX_I);
        assert!(r.search(b"xDEV_0123456789AB", 0).is_some());
        assert!(rx("a.b", 0).search(b"a\nb", 0).is_none());
        assert!(rx("a.b", RX_S).search(b"a\nb", 0).is_some());
    }

    #[test]
    fn match_ve_fullmatch() {
        let r = rx(r"(\d+)", 0);
        assert!(r.match_(b"12ab", 0).is_some());
        assert!(r.match_(b"ab12", 0).is_none());
        assert!(r.match_(b"ab12", 2).is_some());
        assert!(r.fullmatch(b"12ab").is_none());
        assert_eq!(r.fullmatch(b"1234").map(|m| m.group(1)), Some("1234".to_string()));
        let r = rx("a|ab", 0);
        assert!(r.fullmatch(b"ab").is_some());
        assert!(r.search(b"ab", 5).is_none());
        let r = rx("^b", 0);
        assert!(r.search(b"ab", 1).is_none());
        let r = rx("^b", RX_M);
        assert!(r.search(b"a\nb", 1).is_some());
    }

    #[test]
    fn lookahead_ve_geri_basvuru() {
        let r = rx("^(module|hack|feature|function|cheat)(?=[a-z]{3})", 0);
        let m = r.search(b"modulefly", 0).expect("eşleşme");
        assert_eq!(m.end(0), 6);
        assert!(r.search(b"module12", 0).is_none());
        let r = rx(r"(a)\1", 0);
        assert!(r.search(b"xaa", 0).is_some());
        assert!(r.search(b"xab", 0).is_none());
        let r = rx("(?=c)c(\\d)", 0);
        let s = b"\xff\xfe c5";
        let m = r.search(s, 0).expect("eşleşme");
        assert_eq!(m.start(0), 3);
        assert_eq!(m.group(1), "5");
        let s2 = "é c7".as_bytes();
        assert_eq!(r.search(s2, 0).map(|m| m.start(1)), Some(4));
    }

    #[test]
    fn finditer_bos_eslesme() {
        let r = rx("x*", 0);
        let v = r.findall(b"axb");
        let pos: Vec<(usize, usize)> = v.iter().map(|m| (m.start(0), m.end(0))).collect();
        assert_eq!(pos, vec![(0, 0), (1, 2), (2, 2), (3, 3)]);
        let v = r.findall("é".as_bytes());
        let pos: Vec<(usize, usize)> = v.iter().map(|m| (m.start(0), m.end(0))).collect();
        assert_eq!(pos, vec![(0, 0), (2, 2)]);
        let r = rx("x*", RX_BYTES);
        assert_eq!(r.findall("é".as_bytes()).len(), 3);
        let r = rx(r"\d", 0);
        let mut n = 0;
        r.finditer(b"1234", &mut |_| {
            n += 1;
            n < 2
        });
        assert_eq!(n, 2);
    }

    #[test]
    fn unicode_ve_bytes_kipi() {
        assert!(rx(r"^\w+$", 0).search("çağrı".as_bytes(), 0).is_some());
        assert!(rx("ÇAĞ", RX_I).search("çağ".as_bytes(), 0).is_some());
        assert!(rx(r"^\d$", 0).search("٣".as_bytes(), 0).is_some());
        assert!(rx(r"^\w+$", RX_BYTES).search("çağrı".as_bytes(), 0).is_none());
        assert!(rx(r"^\d$", RX_BYTES).search("٣".as_bytes(), 0).is_none());
        let r = rx("\"id\"\\s*:\\s*\"([^\"]+)\"", RX_BYTES);
        let m = r.search(b"{\"id\": \"a\xff\xfeb\"}", 0).expect("eşleşme");
        assert_eq!(m.group_bytes(1), b"a\xff\xfeb");
        let r = rx("\"([^\"]+)\"", 0);
        assert!(r.search(b"\"a\xffb\"", 0).is_none());
        let m = r.search(b"\"ab\"", 0).expect("eşleşme");
        assert_eq!(m.group(1), "ab");
    }

    #[test]
    fn gercek_desenler() {
        let r = rx(
            r"^\[(\d{2}:\d{2}:\d{2})\]|^\[(\d{2}[A-Za-z]{3}\d{4} \d{2}:\d{2}:\d{2}\.\d+)\]|^\[\d",
            0,
        );
        let m = r.match_(b"[12:34:56] [main/INFO]: x", 0).expect("eşleşme");
        assert_eq!(m.group(1), "12:34:56");
        let r = rx(
            r"^\[[^\]]+\] \[main/(?:INFO|DEBUG)\](?: \([^)]*\))?:? (?:\[FabricLoader\] |\[QuiltLoader\] )?Loading (\d+) mods?:\s*(.*)$",
            0,
        );
        let m = r
            .match_(
                b"[12:00:00] [main/INFO] (FabricLoader) [FabricLoader] Loading 3 mods: a, b",
                0,
            )
            .or_else(|| r.match_(b"[12:00:00] [main/INFO]: [FabricLoader] Loading 3 mods: a, b", 0))
            .expect("eşleşme");
        assert_eq!(m.group(1), "3");
        assert_eq!(m.group(2), "a, b");
        let r = rx(r"([A-Za-z0-9_.\-]+)@(\S+?)(?:,|$)", 0);
        let v: Vec<String> = r.findall(b"a@1.0, b@2.0").iter().map(|m| m.group(2)).collect();
        assert_eq!(v, vec!["1.0", "2.0"]);
        let r = rx(r"^\\VOLUME\{[0-9a-fA-F]+-([0-9a-fA-F]+)\}", RX_I);
        assert_eq!(
            r.match_(b"\\VOLUME{01d9-AbCd}\\x", 0).map(|m| m.group(1)),
            Some("AbCd".to_string())
        );
        let r = rx("-javaagent:\\s*\"?([^\"\\r\\n]+?\\.jar)", RX_I);
        assert_eq!(
            r.search(b"-javaagent:\"C:\\a b\\x.jar\" -Xmx", 0).map(|m| m.group(1)),
            Some("C:\\a b\\x.jar".into())
        );
        let r = rx("\"([^\"\\r\\n]+?\\.jar)\"|([^\\s\"';=<>|*?]+\\.jar)\\b", RX_I);
        let v = r.findall(b"-cp \"C:\\a b\\x.jar\" y/z.JAR;");
        assert_eq!(v.len(), 2);
        assert!(v[1].ok(2) && !v[1].ok(1));
    }

    #[test]
    fn gecersiz_desen() {
        let r = Rx::new("(", 0);
        assert!(!r.valid());
        assert!(r.search(b"x", 0).is_none());
        assert!(r.findall(b"x").is_empty());
    }

    #[test]
    fn dolar_yeniden_yazim() {
        assert_eq!(rewrite_dollar("a$").as_deref(), Some("a(?=\\n?\\z)"));
        assert_eq!(rewrite_dollar("[$]"), None);
        assert_eq!(rewrite_dollar("[^]$]x"), None);
        assert_eq!(rewrite_dollar("\\$"), None);
        assert_eq!(rewrite_dollar("[[:alpha:]$]"), None);
    }
}
