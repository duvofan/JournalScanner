use crate::util::*;
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
use windows::Win32::System::EventLog::*;

#[derive(Debug, Clone, Default)]
pub struct EvFinding {
    pub event_id: String,
    pub time: String,
    pub record_id: String,
    pub process: String,
    pub process_field: String,
    pub data: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct EventResult {
    pub available: bool,
    pub error: String,
    pub total_500_501: i32,
    pub findings: Vec<EvFinding>,
}

pub fn scan_ntfs_events(days: i32) -> EventResult {
    let mut r = EventResult::default();
    let mut evs: Vec<RawEvent> = Vec::new();
    let mut err = String::new();
    let mut code = 0i32;
    if !query_event_xml(
        "Microsoft-Windows-Ntfs/Operational",
        &[500, 501],
        days,
        20000,
        &mut evs,
        &mut err,
        Some(&mut code),
    ) {
        if code == 5 {
            r.error = "Günlüğe erişim reddedildi. Programı 'Yönetici olarak çalıştır' ile açın.".to_string();
        } else if code == 15007 || code == 2 {
            r.error = "Ntfs/Operational günlüğü bu sistemde bulunamadı / kapalı.".to_string();
        } else {
            r.error = err;
        }
        return r;
    }
    r.available = true;
    const HINTS: [&str; 8] = [
        "processname",
        "process",
        "imagename",
        "image",
        "processimage",
        "callerprocessname",
        "applicationname",
        "exe",
    ];
    for ev in &evs {
        let Some(root) = ev.root.as_deref() else { continue };
        let Some(sys) = root.child("System") else { continue };
        let eid = sys
            .child("EventID")
            .map(|e| strip(&e.text, WS_CHARS))
            .unwrap_or_default();
        if eid != "500" && eid != "501" {
            continue;
        }
        r.total_500_501 += 1;
        let tc = sys.child("TimeCreated");
        let rec = sys.child("EventRecordID");
        let mut data: Vec<(String, String)> = Vec::new();
        for secname in ["EventData", "UserData"] {
            let Some(sec) = root.child(secname) else { continue };
            let mut all: Vec<&XNode> = Vec::new();
            iter_desc(sec, &mut all);
            for el in all {
                let txt = pystrip(&el.text);
                if txt.is_empty() {
                    continue;
                }
                let mut key = el.attr("Name");
                if key.is_empty() {
                    key = el.tag.clone();
                }
                let mut k = key.clone();
                let mut i = 2;
                while data.iter().any(|kv| kv.0 == k) {
                    k = format!("{}_{}", key, i);
                    i += 1;
                }
                data.push((k, txt));
            }
        }
        let mut proc = String::new();
        let mut field = String::new();
        for kv in &data {
            if has_any(&py_lower(&kv.0), &HINTS) {
                let p = match_process(&kv.1);
                if !p.is_empty() {
                    proc = p;
                    field = kv.0.clone();
                    break;
                }
            }
        }
        if proc.is_empty() {
            for kv in &data {
                let p = match_process(&kv.1);
                if !p.is_empty() {
                    proc = p;
                    field = kv.0.clone();
                    break;
                }
            }
        }
        if proc.is_empty() {
            continue;
        }
        r.findings.push(EvFinding {
            event_id: eid,
            time: fmt_iso_local(&tc.map(|t| t.attr("SystemTime")).unwrap_or_default()),
            record_id: rec.map(|e| strip(&e.text, WS_CHARS)).unwrap_or_default(),
            process: proc,
            process_field: field,
            data,
        });
    }
    r
}

fn match_process(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    let v = strip(&pystrip(value), "\"");
    let low = py_lower(&v);
    let base = match low.rfind(['\\', '/']) {
        Some(k) => &low[k + 1..],
        None => &low[..],
    };
    if base == "fsutil.exe" || base == "fsutil" {
        return "fsutil.exe".to_string();
    }
    if low == "system" {
        return "System".to_string();
    }
    String::new()
}

fn fmt_iso_local(iso: &str) -> String {
    match parse_utc_iso(iso) {
        None => {
            if iso.is_empty() {
                "?".to_string()
            } else {
                iso.to_string()
            }
        }
        Some(t) => fmt_local(t, "%Y-%m-%d %H:%M:%S"),
    }
}

fn iter_desc<'a>(n: &'a XNode, out: &mut Vec<&'a XNode>) {
    for k in &n.kids {
        out.push(k.as_ref());
        iter_desc(k.as_ref(), out);
    }
}

#[derive(Debug, Clone, Default)]
pub struct XNode {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub kids: Vec<Arc<XNode>>,
}
impl XNode {
    pub fn child(&self, t: &str) -> Option<&XNode> {
        self.kids.iter().find(|k| k.tag == t).map(|k| k.as_ref())
    }
    pub fn attr(&self, a: &str) -> String {
        self.attrs
            .iter()
            .find(|kv| kv.0 == a)
            .map(|kv| kv.1.clone())
            .unwrap_or_default()
    }
    pub fn has_attr(&self, a: &str) -> bool {
        self.attrs.iter().any(|kv| kv.0 == a)
    }
}

fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn c_strtoul(s: &str, base: u32) -> u32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && is_space(b[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    if base == 16
        && i + 2 < b.len()
        && b[i] == b'0'
        && (b[i + 1] == b'x' || b[i + 1] == b'X')
        && b[i + 2].is_ascii_hexdigit()
    {
        i += 2;
    }
    let mut v: u64 = 0;
    let mut over = false;
    while i < b.len() {
        let Some(d) = (b[i] as char).to_digit(base) else { break };
        v = v * base as u64 + d as u64;
        if v > u32::MAX as u64 {
            over = true;
            v = u32::MAX as u64;
        }
        i += 1;
    }
    if over {
        return u32::MAX;
    }
    if neg {
        (v as u32).wrapping_neg()
    } else {
        v as u32
    }
}

pub fn xml_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'&' {
            let j = b[i..].iter().position(|&c| c == b'&').map(|x| i + x).unwrap_or(b.len());
            o.push_str(s.get(i..j).unwrap_or(""));
            i = j;
            continue;
        }
        let Some(semi) = b[i..].iter().position(|&c| c == b';').map(|x| i + x) else {
            o.push('&');
            i += 1;
            continue;
        };
        if semi - i > 10 {
            o.push('&');
            i += 1;
            continue;
        }
        let ent = s.get(i + 1..semi).unwrap_or("");
        match ent {
            "lt" => o.push('<'),
            "gt" => o.push('>'),
            "amp" => o.push('&'),
            "quot" => o.push('"'),
            "apos" => o.push('\''),
            _ if ent.starts_with('#') => {
                let eb = ent.as_bytes();
                let cp = if eb.len() > 1 && (eb[1] == b'x' || eb[1] == b'X') {
                    c_strtoul(ent.get(2..).unwrap_or(""), 16)
                } else {
                    c_strtoul(ent.get(1..).unwrap_or(""), 10)
                };
                append_cp(&mut o, cp);
            }
            _ => o.push_str(s.get(i..=semi).unwrap_or("")),
        }
        i = semi + 1;
    }
    o
}

struct Xp<'a> {
    s: &'a str,
    b: &'a [u8],
    p: usize,
    fail: bool,
}

fn local_name(n: &str) -> String {
    match n.rfind(':') {
        Some(c) => n[c + 1..].to_string(),
        None => n.to_string(),
    }
}

impl<'a> Xp<'a> {
    fn skip_ws(&mut self) {
        while self.p < self.b.len() && is_space(self.b[self.p]) {
            self.p += 1;
        }
    }
    fn find(&self, pat: &str, from: usize) -> Option<usize> {
        let pb = pat.as_bytes();
        let h = self.b.get(from..)?;
        h.windows(pb.len()).position(|w| w == pb).map(|x| from + x)
    }
    fn at(&self, pat: &str) -> bool {
        self.b.get(self.p..).is_some_and(|r| r.starts_with(pat.as_bytes()))
    }
    fn sub(&self, a: usize, e: usize) -> &'a str {
        self.s.get(a..e).unwrap_or("")
    }

    fn elem(&mut self, depth: i32) -> Option<Arc<XNode>> {
        if depth > 200 {
            self.fail = true;
            return None;
        }
        self.p += 1;
        let st = self.p;
        while self.p < self.b.len() && !is_space(self.b[self.p]) && self.b[self.p] != b'>' && self.b[self.p] != b'/' {
            self.p += 1;
        }
        let mut n = XNode {
            tag: local_name(self.sub(st, self.p)),
            ..Default::default()
        };
        loop {
            self.skip_ws();
            if self.p >= self.b.len() {
                self.fail = true;
                return None;
            }
            if self.b[self.p] == b'/' {
                if self.p + 1 < self.b.len() && self.b[self.p + 1] == b'>' {
                    self.p += 2;
                    return Some(Arc::new(n));
                }
                self.fail = true;
                return None;
            }
            if self.b[self.p] == b'>' {
                self.p += 1;
                break;
            }
            let an = self.p;
            while self.p < self.b.len() && self.b[self.p] != b'=' && !is_space(self.b[self.p]) && self.b[self.p] != b'>'
            {
                self.p += 1;
            }
            let aname = local_name(self.sub(an, self.p));
            self.skip_ws();
            if self.p >= self.b.len() || self.b[self.p] != b'=' {
                self.fail = true;
                return None;
            }
            self.p += 1;
            self.skip_ws();
            if self.p >= self.b.len() || (self.b[self.p] != b'"' && self.b[self.p] != b'\'') {
                self.fail = true;
                return None;
            }
            let q = self.b[self.p];
            self.p += 1;
            let vs = self.p;
            while self.p < self.b.len() && self.b[self.p] != q {
                self.p += 1;
            }
            if self.p >= self.b.len() {
                self.fail = true;
                return None;
            }
            n.attrs.push((aname, xml_unescape(self.sub(vs, self.p))));
            self.p += 1;
        }
        let mut text_done = false;
        let mut text = String::new();
        while self.p < self.b.len() {
            if self.b[self.p] == b'<' {
                if self.at("<!--") {
                    self.p = self.find("-->", self.p).map(|e| e + 3).unwrap_or(self.b.len());
                    continue;
                }
                if self.at("<![CDATA[") {
                    let e = self.find("]]>", self.p);
                    let end = e.unwrap_or(self.b.len());
                    if !text_done {
                        text.push_str(self.sub(self.p + 9, end));
                    }
                    self.p = e.map(|e| e + 3).unwrap_or(self.b.len());
                    continue;
                }
                if self.at("</") {
                    self.p = self.b[self.p..]
                        .iter()
                        .position(|&c| c == b'>')
                        .map(|x| self.p + x + 1)
                        .unwrap_or(self.b.len());
                    if !text_done {
                        n.text = text;
                    }
                    return Some(Arc::new(n));
                }
                if self.at("<?") {
                    self.p = self.find("?>", self.p).map(|e| e + 2).unwrap_or(self.b.len());
                    continue;
                }
                if !text_done {
                    n.text = std::mem::take(&mut text);
                    text_done = true;
                }
                let c = self.elem(depth + 1);
                if self.fail {
                    return None;
                }
                n.kids.push(c?);
                continue;
            }
            let e = self.b[self.p..]
                .iter()
                .position(|&c| c == b'<')
                .map(|x| self.p + x)
                .unwrap_or(self.b.len());
            if !text_done {
                text.push_str(&xml_unescape(self.sub(self.p, e)));
            }
            self.p = e;
        }
        self.fail = true;
        None
    }
}

pub fn xml_parse(s: &str) -> Option<Arc<XNode>> {
    let mut x = Xp {
        s,
        b: s.as_bytes(),
        p: 0,
        fail: false,
    };
    while x.p < s.len() {
        let lt = x.b[x.p..].iter().position(|&c| c == b'<').map(|v| x.p + v)?;
        x.p = lt;
        if x.at("<?") || x.at("<!--") || x.at("<!") {
            let e = x.b[lt..].iter().position(|&c| c == b'>').map(|v| lt + v)?;
            x.p = e + 1;
            continue;
        }
        let r = x.elem(0);
        if x.fail {
            return None;
        }
        return r;
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct RawEvent {
    pub root: Option<Arc<XNode>>,
    pub xml: String,
}

fn wide_z(s: &str) -> Vec<u16> {
    let mut w = widen(s);
    if w.last() != Some(&0) {
        w.push(0);
    }
    w
}

fn render_xml(eh: EVT_HANDLE, buf: &mut Vec<u16>) -> u32 {
    let mut used = 0u32;
    let mut props = 0u32;
    // SAFETY: buf bildirilen bayt boyutu kadar yazılabilir; used / props geçerli çıktı işaretçileri.
    let r = unsafe {
        EvtRender(
            None,
            eh,
            EvtRenderEventXml.0,
            (buf.len() * 2) as u32,
            Some(buf.as_mut_ptr() as *mut _),
            &mut used,
            &mut props,
        )
    };
    if r.is_ok() {
        return used;
    }
    // SAFETY: yalnızca iş parçacığının son hata kodunu okur.
    if unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER {
        buf.clear();
        buf.resize(used as usize / 2 + 16, 0);
        // SAFETY: yukarıdakiyle aynı.
        let r2 = unsafe {
            EvtRender(
                None,
                eh,
                EvtRenderEventXml.0,
                (buf.len() * 2) as u32,
                Some(buf.as_mut_ptr() as *mut _),
                &mut used,
                &mut props,
            )
        };
        if r2.is_ok() {
            return used;
        }
    }
    0
}

pub fn query_event_xml(
    channel: &str,
    ids: &[i32],
    days: i32,
    max_count: i32,
    out: &mut Vec<RawEvent>,
    err: &mut String,
    err_code: Option<&mut i32>,
) -> bool {
    out.clear();
    let ms = days as i64 * 86400i64 * 1000i64;
    let mut q = String::from("*[System[(");
    for (i, id) in ids.iter().enumerate() {
        if i > 0 {
            q.push_str(" or ");
        }
        q.push_str(&format!("EventID={}", id));
    }
    q.push_str(&format!(") and TimeCreated[timediff(@SystemTime) <= {}]]]", ms));
    let wchan = wide_z(channel);
    let wq = wide_z(&q);
    // SAFETY: işaretçiler çağrı süresince geçerli, NUL sonlu UTF-16 tamponlarına işaret eder.
    let h = unsafe {
        EvtQuery(
            None,
            PCWSTR(wchan.as_ptr()),
            PCWSTR(wq.as_ptr()),
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        )
    };
    let h = match h {
        Ok(h) => h,
        Err(_) => {
            // SAFETY: yalnızca son hata kodunu okur.
            let e = unsafe { GetLastError() }.0;
            if let Some(c) = err_code {
                *c = e as i32;
            }
            *err = format!("olay günlüğü hatası {}", e);
            return false;
        }
    };
    let mut evs = [0isize; 64];
    let mut ret: u32 = 0;
    let mut buf: Vec<u16> = vec![0; 8192];
    let mut count = 0;
    // SAFETY: evs 64 elemanlıdır; ret geçerli bir çıktı işaretçisidir.
    while count < max_count && unsafe { EvtNext(h, &mut evs, 5000, 0, &mut ret) }.is_ok() {
        for ev in evs.iter().take(ret as usize) {
            let eh = EVT_HANDLE(*ev);
            let used = render_xml(eh, &mut buf);
            if used != 0 {
                let mut n = (used as usize / 2).min(buf.len());
                while n > 0 && buf[n - 1] == 0 {
                    n -= 1;
                }
                let xml = narrow(&buf[..n]);
                let root = xml_parse(&xml);
                if root.is_some() {
                    out.push(RawEvent { root, xml });
                }
            }
            // SAFETY: eh, EvtNext'ten gelen geçerli bir tanıtıcıdır.
            let _ = unsafe { EvtClose(eh) };
            count += 1;
        }
    }
    // SAFETY: h, EvtQuery'den gelen geçerli bir tanıtıcıdır.
    let _ = unsafe { EvtClose(h) };
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>500</EventID>\
        <TimeCreated SystemTime='2026-10-20T11:02:03.1234567Z'/><EventRecordID>77</EventRecordID></System>\
        <EventData><Data Name='ProcessName'>C:\\Windows\\System32\\fsutil.exe</Data><Data>a &amp; b</Data></EventData></Event>";

    #[test]
    fn xml_basic() {
        let r = xml_parse(SAMPLE).expect("parse");
        assert_eq!(r.tag, "Event");
        let sys = r.child("System").unwrap();
        assert_eq!(sys.child("EventID").unwrap().text, "500");
        assert_eq!(
            sys.child("TimeCreated").unwrap().attr("SystemTime"),
            "2026-10-20T11:02:03.1234567Z"
        );
        assert!(sys.child("TimeCreated").unwrap().has_attr("SystemTime"));
        let ed = r.child("EventData").unwrap();
        assert_eq!(ed.kids.len(), 2);
        assert_eq!(ed.kids[1].text, "a & b");
        assert_eq!(ed.kids[0].attr("Name"), "ProcessName");
    }

    #[test]
    fn xml_bad() {
        assert!(xml_parse("").is_none());
        assert!(xml_parse("<a>").is_none());
        assert!(xml_parse("<a b=c/>").is_none());
        assert!(xml_parse("<a b='x").is_none());
        assert!(xml_parse(&"<a>".repeat(300)).is_none());
    }

    #[test]
    fn xml_prolog_comment_cdata() {
        let r = xml_parse("<?xml version='1.0'?><!-- c --><x:a><![CDATA[1<2]]>t<b/>tail</x:a>").unwrap();
        assert_eq!(r.tag, "a");
        assert_eq!(r.text, "1<2t");
        assert_eq!(r.kids.len(), 1);
    }

    #[test]
    fn unescape_named() {
        assert_eq!(xml_unescape("&lt;a&gt; &amp; &quot;q&quot; &apos;"), "<a> & \"q\" '");
        assert_eq!(xml_unescape("&unknown; &"), "&unknown; &");
        assert_eq!(xml_unescape("&averyveryverylongentity;"), "&averyveryverylongentity;");
    }

    #[test]
    fn strtoul_c() {
        assert_eq!(c_strtoul("65", 10), 65);
        assert_eq!(c_strtoul("41", 16), 0x41);
        assert_eq!(c_strtoul("0x41", 16), 0x41);
        assert_eq!(c_strtoul("", 10), 0);
        assert_eq!(c_strtoul("99999999999", 10), u32::MAX);
        assert_eq!(c_strtoul("12zz", 10), 12);
    }
}
