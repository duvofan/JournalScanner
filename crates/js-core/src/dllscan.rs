use crate::util::*;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct DllFinding {
    pub id: String,
    pub name: String,
    pub verdict: String,
    pub tag: char,
    pub path: String,
    pub r#where: String,
    pub reason: String,
    pub detail: Vec<String>,
}
impl Default for DllFinding {
    fn default() -> Self {
        DllFinding {
            id: String::new(),
            name: String::new(),
            verdict: String::new(),
            tag: 'i',
            path: String::new(),
            r#where: String::new(),
            reason: String::new(),
            detail: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DllScanResult {
    pub ran: bool,
    pub have_tool: bool,
    pub error: String,
    pub kesin: i32,
    pub supheli: i32,
    pub javaw_active: bool,
    pub javaw_seen: bool,
    pub javaw_no_access: bool,
    pub verdict: String,
    pub summary: String,
    pub overview: Vec<String>,
    pub findings: Vec<DllFinding>,
    pub mem_overview: StrList,
    pub full_log: String,
    pub duration: f64,
}
impl Default for DllScanResult {
    fn default() -> Self {
        DllScanResult {
            ran: false,
            have_tool: true,
            error: String::new(),
            kesin: 0,
            supheli: 0,
            javaw_active: false,
            javaw_seen: false,
            javaw_no_access: false,
            verdict: String::new(),
            summary: String::new(),
            overview: Vec::new(),
            findings: Vec::new(),
            mem_overview: Vec::new(),
            full_log: String::new(),
            duration: 0.0,
        }
    }
}

fn rstrip_sp(s: &str) -> &str {
    s.trim_end_matches([' ', '\t', '\r'])
}
fn lstrip_sp(s: &str) -> &str {
    s.trim_start_matches([' ', '\t'])
}
fn kv_row(line: &str) -> (String, String) {
    let s = lstrip_sp(line);
    if let Some(c) = s.find(" : ") {
        return (rstrip_sp(&s[..c]).to_string(), lstrip_sp(&s[c + 3..]).to_string());
    }
    if let Some(c2) = s.find(':') {
        return (rstrip_sp(&s[..c2]).to_string(), lstrip_sp(&s[c2 + 1..]).to_string());
    }
    (String::new(), String::new())
}
fn c_atoi(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = (v * 10 + (b[i] - b'0') as i64).min(i32::MAX as i64 + 1);
        i += 1;
    }
    if neg {
        v = -v;
    }
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}
fn bat(s: &str, i: usize) -> u8 {
    s.as_bytes().get(i).copied().unwrap_or(0)
}
fn lower(s: &str) -> String {
    s.to_lowercase()
}

pub fn parse_dll_log(log: &str) -> DllScanResult {
    let lines = splitlines(log);
    parse_lines(log, &lines)
}

fn parse_lines(log: &str, lines: &[String]) -> DllScanResult {
    let mut r = DllScanResult {
        full_log: log.to_string(),
        ..Default::default()
    };
    let nl = lines.len() as i64;
    let flines: Vec<String> = lines.iter().map(|l| katla(l)).collect();

    let (mut i_sonuclar, mut i_toplu, mut i_sonuc) = (-1i64, -1i64, -1i64);
    for (i, l) in flines.iter().enumerate() {
        let i = i as i64;
        if i_sonuclar < 0 && l.contains("SONUCLAR (KESIN") {
            i_sonuclar = i;
        }
        if i_toplu < 0 && l.contains("TOPLU SONUC TABLOSU") {
            i_toplu = i;
        }
        if l.contains("SONUC:") {
            i_sonuc = i;
        }
    }

    let mut have_status = false;
    let mut phase_ran = false;
    for (li, l0) in lines.iter().enumerate() {
        let l = &flines[li];
        let s = lstrip_sp(l);
        if s.contains("JAVAW_DURUM:") {
            have_status = true;
            let num = |key: &str| -> i32 {
                match s.find(key) {
                    None => 0,
                    Some(p) => c_atoi(&s[p + key.len()..]),
                }
            };
            let seen = num("bulunan=");
            let acc = num("erisilen=");
            let fail = num("erisilemeyen=");
            r.javaw_seen = seen > 0 || acc > 0;
            r.javaw_active = acc > 0;
            r.javaw_no_access = acc == 0 && fail > 0;
        }
        if s.len() > 5 && bat(s, 0) == b'[' && (b'1'..=b'7').contains(&bat(s, 1)) && bat(s, 2) == b'/' {
            let ls = lower(s);
            if !ls.contains("atlandi") && !ls.contains("javaw yok") {
                phase_ran = true;
            }
        }
        if s.len() > 5 && bat(s, 0) == b'[' && bat(s, 1).is_ascii_digit() {
            r.overview.push(rstrip_sp(l0).to_string());
        }
        if (s.contains("Taranacak:") && s.contains("bolge"))
            || (s.contains("Tamamlandi:") && s.contains("string cikarildi"))
            || s.contains("Heap stringlerinde")
            || s.contains("cumle/sohbet metni")
            || s.contains("[6/9]")
        {
            r.mem_overview.push(rstrip_sp(l0).to_string());
        }
    }
    if !have_status {
        r.javaw_active = phase_ran;
        r.javaw_seen = phase_ran;
    }

    if i_sonuc >= 0 {
        let isn = i_sonuc as usize;
        r.summary = rstrip_sp(lstrip_sp(&lines[isn])).to_string();
        let su = lower(&katla(&r.summary));
        if su.contains("kesin") {
            r.verdict = "KESIN HILE".to_string();
        } else if su.contains("supheli") || su.contains("incele") {
            r.verdict = "SUPHELI".to_string();
        } else {
            r.verdict = "TEMIZ".to_string();
        }
        r.overview.push(String::new());
        let mut i = (i_sonuc - 1).max(0);
        while i < nl && i <= i_sonuc + 3 {
            let t = rstrip_sp(&lines[i as usize]);
            if !t.is_empty() && !t.contains("===") {
                r.overview.push(t.to_string());
            }
            i += 1;
        }
    } else {
        r.verdict = "TEMIZ".to_string();
    }

    let mut cards: BTreeMap<String, Vec<String>> = BTreeMap::new(); // anahtar: lower(yol)
    let mut cards_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new(); // anahtar: lower(ad)
    if i_sonuclar >= 0 {
        let end = if i_toplu > i_sonuclar { i_toplu } else { nl };
        let mut c = i_sonuclar + 1;
        while c < end {
            let s = lstrip_sp(&lines[c as usize]);
            if s.len() > 4 && bat(s, 0) == b'[' && bat(s, 1).is_ascii_digit() {
                if let Some(rb) = s.find("] ") {
                    let rest = &s[rb + 2..];
                    let name = match rest.find("   ") {
                        None => "",
                        Some(sep) => lstrip_sp(&rest[sep + 3..]),
                    };
                    let mut body: Vec<String> = vec![rstrip_sp(&lines[c as usize]).to_string()];
                    let mut d = c + 1;
                    let mut ypath = String::new();
                    while d < end {
                        let ds = lstrip_sp(&lines[d as usize]);
                        if ds.len() > 4
                            && bat(ds, 0) == b'['
                            && bat(ds, 1).is_ascii_digit()
                            && ds.contains("] ")
                            && !ds.contains('+')
                        {
                            break; // sonraki kart
                        }
                        body.push(rstrip_sp(&lines[d as usize]).to_string());
                        let kv = kv_row(&lines[d as usize]);
                        if kv.0 == "Yol" && ypath.is_empty() {
                            ypath = kv.1;
                        }
                        d += 1;
                    }
                    if !ypath.is_empty() {
                        cards.insert(lower(&ypath), body.clone());
                    }
                    if !name.is_empty() {
                        cards_by_name.insert(lower(name), body);
                    }
                    c = d;
                    continue;
                }
            }
            c += 1;
        }
    }

    if i_toplu >= 0 {
        let mut i = i_toplu + 1;
        while i < nl {
            let l = &lines[i as usize];
            let s = lstrip_sp(l);
            let fl = &flines[i as usize];
            if fl.contains("KIRMIZI") && fl.contains("KESIN") {
                r.kesin = c_atoi(&kv_row(l).1);
            } else if fl.contains("SARI") && fl.contains("SUPHELI") {
                r.supheli = c_atoi(&kv_row(l).1);
            }
            if s.len() > 4
                && bat(s, 0) == b'['
                && (bat(s, 1) == b'K' || bat(s, 1) == b'S')
                && bat(s, 2).is_ascii_digit()
            {
                let Some(rb) = s.find("] ") else {
                    i += 1;
                    continue;
                };
                let kind = bat(s, 1) as char;
                let rest = &s[rb + 2..];
                let mut name = rest.to_string();
                let mut typ = String::new();
                if let Some(lt) = rest.rfind("   <") {
                    if rest.ends_with('>') {
                        name = rstrip_sp(&rest[..lt]).to_string();
                        typ = rest.get(lt + 4..rest.len() - 1).unwrap_or("").to_string();
                    }
                }
                let mut f = DllFinding {
                    id: format!("{}{}", kind, r.findings.len()),
                    name,
                    verdict: if kind == 'K' { "KESIN HILE" } else { "SUPHELI" }.to_string(),
                    tag: if kind == 'K' { 'k' } else { 's' },
                    r#where: typ,
                    ..Default::default()
                };
                let mut d = i + 1;
                let mut sub: Vec<String> = Vec::new();
                while d < nl {
                    let ds = lstrip_sp(&lines[d as usize]);
                    let fds = lstrip_sp(&flines[d as usize]);
                    if ds.is_empty() {
                        d += 1;
                        continue;
                    }
                    if bat(ds, 0) == b'[' && (bat(ds, 1) == b'K' || bat(ds, 1) == b'S') && bat(ds, 2).is_ascii_digit() {
                        break;
                    }
                    if fds.contains("Tur bazinda")
                        || fds.contains("SELF-DESTRUCT / GECMIS")
                        || fds.contains("ARAMA TURLERI")
                        || lines[d as usize].contains("===")
                        || fds.contains("SARI (SUPHELI)")
                    {
                        break;
                    }
                    let kv = kv_row(&lines[d as usize]);
                    match kv.0.as_str() {
                        "dosya" => f.path = kv.1,
                        "yer" => f.r#where = kv.1,
                        "neden" => f.reason = kv.1,
                        _ => {}
                    }
                    sub.push(rstrip_sp(&lines[d as usize]).to_string());
                    d += 1;
                }
                let mut det: Vec<String> = Vec::new();
                if let Some(v) = cards.get(&lower(&f.path)) {
                    det = v.clone();
                } else if let Some(v) = cards_by_name.get(&lower(&f.name)) {
                    det = v.clone();
                }
                if det.is_empty() {
                    det.push(format!("[{}]  {}", goster_buyuk(&f.verdict), f.name));
                    for x in &sub {
                        det.push(format!("  {}", x));
                    }
                }
                while let Some(last) = det.last() {
                    let t = rstrip_sp(last);
                    let sepline = !t.is_empty() && t.chars().all(|c| c == ' ' || c == '=');
                    if t.is_empty() || sepline {
                        det.pop();
                    } else {
                        break;
                    }
                }
                f.detail = det;
                r.findings.push(f);
                i = d - 1;
            }
            i += 1;
        }
    }

    let kk = r.findings.iter().filter(|f| f.tag == 'k').count() as i32;
    let ss = r.findings.iter().filter(|f| f.tag == 's').count() as i32;
    if kk > r.kesin {
        r.kesin = kk;
    }
    if ss > r.supheli {
        r.supheli = ss;
    }
    if r.verdict.is_empty() {
        r.verdict = if r.kesin != 0 {
            "KESIN HILE"
        } else if r.supheli != 0 {
            "SUPHELI"
        } else {
            "TEMIZ"
        }
        .to_string();
    }
    r.ran = true;
    r
}

pub fn dll_finding_is_memory(f: &DllFinding) -> bool {
    let w = katla(&f.r#where).to_uppercase();
    ["BELLEK", "HEAP", "ENJEKSIYON", "UNBACKED"]
        .iter()
        .any(|m| w.contains(m))
}

pub fn dll_tool_path() -> String {
    self_exe_path()
}

#[cfg(windows)]
fn quote_arg(a: &str) -> String {
    if !a.contains(' ') && !a.contains('"') {
        return a.to_string();
    }
    let mut o = String::from("\"");
    for c in a.chars() {
        if c == '"' {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('"');
    o
}

#[cfg(windows)]
pub fn scan_dll(
    roots: &[String],
    no_disk: bool,
    progress: Option<StrProgress>,
    stop: Option<&StopFlag>,
) -> DllScanResult {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Duration;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let mut r = DllScanResult::default();
    let tool = dll_tool_path();
    if tool.is_empty() {
        r.have_tool = false;
        r.error = "Programın kendi yolu alınamadı; DLL tarayıcısı başlatılamadı.".to_string();
        return r;
    }
    let tdir = make_temp_dir("jsdll");
    let logp = path_join(&tdir, "avdll_log.txt");

    let mut cmd = Command::new(&tool);
    cmd.args(["--avdll", "--nopause", "--verbose"]);
    cmd.raw_arg(quote_arg(&format!("--log={}", logp)));
    if no_disk {
        cmd.arg("--nodisk");
    }
    for rt in roots {
        if !rt.is_empty() {
            cmd.raw_arg(quote_arg(&format!("--root={}", rt)));
        }
    }
    cmd.current_dir(path_dirname(&tool));
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    cmd.creation_flags(CREATE_NO_WINDOW);

    if let Some(p) = progress {
        p("DLL / yerel modül tarayıcı çalışıyor...");
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            r.error = format!(
                "DLL tarayıcısı başlatılamadı (hata {}). Yönetici izni gerekebilir.",
                e.raw_os_error().unwrap_or(0)
            );
            return r;
        }
    };
    let t0 = now_epoch();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if stop.is_some_and(|s| s.is_set()) {
            let _ = child.kill();
            let _ = child.wait();
            r.error = "Tarama durduruldu.".to_string();
            break;
        }
        if now_epoch() - t0 > 900.0 {
            let _ = child.kill();
            r.error = "DLL taraması zaman aşımına uğradı (15 dk).".to_string();
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    drop(child);

    let data = match read_file(&logp, -1, 0) {
        Some(d) if !d.is_empty() => d,
        _ => {
            if r.error.is_empty() {
                r.error = "DLL tarayıcısı çıktı üretmedi (log boş).".to_string();
            }
            return r;
        }
    };
    r = parse_dll_log(&String::from_utf8_lossy(&data));
    r.duration = now_epoch() - t0;
    if !r.have_tool {
        r.have_tool = true;
    }
    r
}

#[cfg(not(windows))]
pub fn scan_dll(
    _roots: &[String],
    _no_disk: bool,
    _progress: Option<StrProgress>,
    _stop: Option<&StopFlag>,
) -> DllScanResult {
    DllScanResult {
        error: "DLL taraması yalnızca Windows'ta çalışır.".to_string(),
        have_tool: false,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(log: &str) -> DllScanResult {
        let lines: Vec<String> = log.split('\n').map(|s| s.to_string()).collect();
        parse_lines(log, &lines)
    }

    const LOG: &str = "\
[1/9] Süreçler tarandı
[6/9] Bellek taraması
  Taranacak: 12 bölge
  JAVAW_DURUM: bulunan=1 erişilen=1 erişilemeyen=0
================
  SONUÇLAR (KESIN bulgular + şüpheliler)
================
[1] KESIN HILE   evil.dll
   Yol         : C:\\mods\\evil.dll
   SHA-256     : abc
================
  TOPLU SONUÇ TABLOSU  -  özet
  KIRMIZI (KESIN)   : 1
  SARI (SUPHELI)    : 1
  [K1] evil.dll   <DİSK>
     dosya : C:\\mods\\evil.dll
     yer   : diskte
     neden : imza
  [S2] foo.dll   <BELLEK>
     neden : şüphe
================
  SONUÇ: HILE TESPİT EDİLDİ (KESIN)  -  1 bulgu
";

    #[test]
    fn full_log() {
        let r = parse(LOG);
        assert!(r.ran);
        assert_eq!(r.verdict, "KESIN HILE");
        assert!(r.javaw_active && r.javaw_seen && !r.javaw_no_access);
        assert_eq!(r.kesin, 1);
        assert_eq!(r.supheli, 1);
        assert_eq!(r.findings.len(), 2);
        let f = &r.findings[0];
        assert_eq!(f.id, "K0");
        assert_eq!(f.name, "evil.dll");
        assert_eq!(f.tag, 'k');
        assert_eq!(f.path, "C:\\mods\\evil.dll");
        assert_eq!(f.r#where, "diskte");
        assert_eq!(f.reason, "imza");
        assert_eq!(f.detail[0], "[1] KESIN HILE   evil.dll");
        assert!(!dll_finding_is_memory(f));
        let g = &r.findings[1];
        assert_eq!(g.id, "S1");
        assert_eq!(g.r#where, "BELLEK");
        assert_eq!(g.detail[0], "[ŞÜPHELİ]  foo.dll");
        assert!(dll_finding_is_memory(g));
        assert!(r.summary.starts_with("SONUÇ:"));
        assert_eq!(r.mem_overview.len(), 2);
        assert!(r.overview.iter().any(|l| l.starts_with("[1/9]")));
    }

    const LOG_TR: &str = "[1/9] Süreçler tarandı
[6/9] Bellek taraması
  Taranacak: 12 bölge
  Tamamlandı: 1 string çıkarıldı
  JAVAW_DURUM: bulunan=1 erişilen=1 erişilemeyen=0
================
  SONUÇLAR (KESİN bulgular + şüpheliler)
================
[1] KESİN HİLE   evil.dll
   Yol         : C:\\mods\\evil.dll
================
  TOPLU SONUÇ TABLOSU  -  özet
  KIRMIZI (KESİN HİLE): 1
  SARI (ŞÜPHELİ): 1
  [K1] evil.dll   <DİSK>
     dosya : C:\\mods\\evil.dll
     yer   : diskte
     neden : imza
  [S2] foo.dll   <ENJEKSİYON>
     neden : şüphe
================
  SONUÇ: HİLE TESPİT EDİLDİ (KESİN)  -  1 bulgu
";

    #[test]
    fn turkce_karakterli_log_ascii_ile_ayni() {
        let tr = parse(LOG_TR);
        let ascii = parse(&katla(LOG_TR));
        assert_eq!(tr.verdict, "KESIN HILE");
        assert_eq!(tr.verdict, ascii.verdict);
        assert!(tr.javaw_active && tr.javaw_seen && !tr.javaw_no_access);
        assert_eq!(
            (tr.javaw_active, tr.javaw_seen, tr.javaw_no_access),
            (ascii.javaw_active, ascii.javaw_seen, ascii.javaw_no_access)
        );
        assert_eq!((tr.kesin, tr.supheli), (1, 1));
        assert_eq!((tr.kesin, tr.supheli), (ascii.kesin, ascii.supheli));
        assert_eq!(tr.findings.len(), 2);
        assert_eq!(tr.findings.len(), ascii.findings.len());
        assert_eq!(tr.mem_overview.len(), 3);
        assert_eq!(tr.mem_overview.len(), ascii.mem_overview.len());
        assert_eq!(tr.overview.len(), ascii.overview.len());
        for (a, b) in tr.findings.iter().zip(&ascii.findings) {
            assert_eq!((&a.id, a.tag, &a.verdict), (&b.id, b.tag, &b.verdict));
            assert_eq!(katla(&a.r#where), katla(&b.r#where));
            assert_eq!(dll_finding_is_memory(a), dll_finding_is_memory(b));
        }
        assert!(tr.findings[0].detail[0].starts_with("[1] KESİN HİLE"));
        assert!(dll_finding_is_memory(&tr.findings[1]));
        assert!(tr.summary.starts_with("SONUÇ:"));
    }

    #[test]
    fn clean_and_empty() {
        let r = parse("SONUÇ: HILE BULUNAMADI\n");
        assert_eq!(r.verdict, "TEMIZ");
        assert_eq!(r.kesin, 0);
        let r = parse("");
        assert_eq!(r.verdict, "TEMIZ");
        assert!(r.ran);
        let r = parse("SONUÇ: SUPHELI BULGU VAR (kesin değil)\n");
        assert_eq!(r.verdict, "KESIN HILE");
    }

    #[test]
    fn javaw_status_variants() {
        let r = parse("JAVAW_DURUM: bulunan=1 erişilen=0 erişilemeyen=1\n");
        assert!(r.javaw_seen && !r.javaw_active && r.javaw_no_access);
        let r = parse("[3/9] taraniyor\n");
        assert!(r.javaw_active && r.javaw_seen);
        let r = parse("[3/9] atlandi\n");
        assert!(!r.javaw_active);
    }

    #[test]
    fn malformed_input_no_panic() {
        for log in [
            "[",
            "[K",
            "[K1",
            "[K1]",
            "[K1] ",
            "TOPLU SONUÇ TABLOSU\n[K1] x   <",
            "TOPLU SONUÇ TABLOSU\n[S9] ğ   <>\n  dosya",
        ] {
            let _ = parse(log);
        }
        let r = parse("SONUÇLAR (KESIN\n[1] ğü\n[2]\n");
        assert!(r.ran);
    }

    #[test]
    fn helpers() {
        assert_eq!(c_atoi("  12abc"), 12);
        assert_eq!(c_atoi("-5"), -5);
        assert_eq!(c_atoi("x"), 0);
        assert_eq!(c_atoi("99999999999999"), i32::MAX);
        assert_eq!(kv_row("  key   : val  "), ("key".to_string(), "val  ".to_string()));
        assert_eq!(kv_row("a:b"), ("a".to_string(), "b".to_string()));
    }

    #[cfg(windows)]
    #[test]
    fn quoting() {
        assert_eq!(quote_arg("--log=C:\\a b\\c"), "\"--log=C:\\a b\\c\"");
        assert_eq!(quote_arg("x"), "x");
    }
}
