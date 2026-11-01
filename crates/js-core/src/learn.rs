use crate::dllscan::{dll_finding_is_memory, DllFinding};
use crate::jar::{category_rank, verdict_by_rank, ScanResult};
use crate::logs::verified_id;
use crate::util::*;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Clone, Default)]
pub struct LearnRec {
    pub key: String,
    pub kind: String,
    pub name: String,
    pub path: String,
    pub source: String,
    pub verdict: String,
    pub mod_id: String,
    pub mod_name: String,
    pub version: String,
    pub loader: String,
    pub sha256: String,
    pub size: u64,
    pub packages: String,
    pub mixins: String,
    pub findings: String,
    pub first_seen: String,
    pub last_seen: String,
    pub seen: i32,
    pub rank: i32,
}

#[derive(Default)]
struct State {
    loaded: bool,
    dirty: bool,
    recs: BTreeMap<String, LearnRec>,
    path: String,
}

static STATE: Mutex<State> = Mutex::new(State {
    loaded: false,
    dirty: false,
    recs: BTreeMap::new(),
    path: String::new(),
});

fn lock() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

fn mkdir_one(d: &str) -> bool {
    match std::fs::create_dir(d) {
        Ok(()) => true,
        Err(e) => e.kind() == std::io::ErrorKind::AlreadyExists,
    }
}

fn writable_dir(d: &str) -> bool {
    let probe = path_join(d, ".js_yazma_testi");
    if !write_file(&probe, b"x") {
        return false;
    }
    let _ = std::fs::remove_file(&probe);
    true
}

fn choose_path() -> String {
    let ov = env("JS_LEARN_PATH"); // testler için
    if !ov.is_empty() {
        return ov;
    }
    let dir = path_dirname(&self_exe_path());
    if !dir.is_empty() && writable_dir(&dir) {
        return path_join(&dir, "JournalScanner_hafiza.txt");
    }
    let la = env("LOCALAPPDATA");
    if !la.is_empty() {
        let d = path_join(&la, "JournalScanner");
        if mkdir_one(&d) && writable_dir(&d) {
            return path_join(&d, "JournalScanner_hafiza.txt");
        }
    }
    path_join(if dir.is_empty() { "." } else { &dir }, "JournalScanner_hafiza.txt")
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

fn c_strtoull(s: &str) -> u64 {
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
    let mut v: u64 = 0;
    let mut over = false;
    while i < b.len() && b[i].is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add((b[i] - b'0') as u64)) {
            Some(x) => v = x,
            None => over = true,
        }
        i += 1;
    }
    if over {
        return u64::MAX;
    }
    if neg {
        v.wrapping_neg()
    } else {
        v
    }
}

fn parse_store(recs: &mut BTreeMap<String, LearnRec>, txt: &str) {
    let mut cur = LearnRec::default();
    let mut inside = false;
    fn flush(recs: &mut BTreeMap<String, LearnRec>, cur: &mut LearnRec, inside: bool) {
        if inside && !cur.key.is_empty() {
            recs.insert(cur.key.clone(), cur.clone());
        }
        *cur = LearnRec::default();
    }
    for ln in txt.replace("\r\n", "\n").split('\n') {
        if ln == "[kayit]" {
            flush(recs, &mut cur, inside);
            inside = true;
            continue;
        }
        if !inside || ln.is_empty() || ln.starts_with('#') {
            continue;
        }
        let Some(eq) = ln.find('=') else { continue };
        let (k, v) = (&ln[..eq], &ln[eq + 1..]);
        match k {
            "key" => cur.key = v.to_string(),
            "kind" => cur.kind = v.to_string(),
            "name" => cur.name = v.to_string(),
            "path" => cur.path = v.to_string(),
            "source" => cur.source = v.to_string(),
            "verdict" => cur.verdict = v.to_string(),
            "mod_id" => cur.mod_id = v.to_string(),
            "mod_name" => cur.mod_name = v.to_string(),
            "version" => cur.version = v.to_string(),
            "loader" => cur.loader = v.to_string(),
            "sha256" => cur.sha256 = v.to_string(),
            "size" => cur.size = c_strtoull(v),
            "packages" => cur.packages = v.to_string(),
            "mixins" => cur.mixins = v.to_string(),
            "findings" => cur.findings = v.to_string(),
            "first_seen" => cur.first_seen = v.to_string(),
            "last_seen" => cur.last_seen = v.to_string(),
            "seen" => cur.seen = c_atoi(v),
            "rank" => cur.rank = c_atoi(v),
            _ => {}
        }
    }
    flush(recs, &mut cur, inside);
}

fn serialize(recs: &BTreeMap<String, LearnRec>) -> String {
    let mut o = String::from(
        "# JournalScanner HAFIZA - imza listesinde OLMAYAN, davranışından yakalanan hileler\n\
         # Bu dosyayı elle düzenlemeyin. Dışarı aktarmak için programdaki 'Yeni Hile Listesi' düğmesini kullanın.\n",
    );
    for r in recs.values() {
        o += "[kayit]\n";
        o += &format!("key={}\n", one_line(&r.key));
        o += &format!("kind={}\n", one_line(&r.kind));
        o += &format!("name={}\n", one_line(&r.name));
        o += &format!("path={}\n", one_line(&r.path));
        o += &format!("source={}\n", one_line(&r.source));
        o += &format!("verdict={}\n", one_line(&r.verdict));
        o += &format!("rank={}\n", r.rank);
        o += &format!("mod_id={}\n", one_line(&r.mod_id));
        o += &format!("mod_name={}\n", one_line(&r.mod_name));
        o += &format!("version={}\n", one_line(&r.version));
        o += &format!("loader={}\n", one_line(&r.loader));
        o += &format!("sha256={}\n", one_line(&r.sha256));
        o += &format!("size={}\n", r.size);
        o += &format!("packages={}\n", one_line(&r.packages));
        o += &format!("mixins={}\n", one_line(&r.mixins));
        o += &format!("findings={}\n", one_line(&r.findings));
        o += &format!("first_seen={}\n", one_line(&r.first_seen));
        o += &format!("last_seen={}\n", one_line(&r.last_seen));
        o += &format!("seen={}\n", r.seen);
    }
    o
}

fn load_locked(st: &mut State) {
    if st.loaded {
        return;
    }
    st.loaded = true;
    st.path = choose_path();
    if let Some(d) = read_file(&st.path, 64 << 20, 0) {
        let txt = utf8_decode(&d, 1);
        parse_store(&mut st.recs, &txt);
    }
}

fn upsert_locked(st: &mut State, r: LearnRec) {
    let now = fmt_dt(Some(now_epoch()));
    upsert_at(st, r, &now);
}

fn upsert_at(st: &mut State, mut r: LearnRec, now: &str) {
    match st.recs.get_mut(&r.key) {
        None => {
            r.first_seen = now.to_string();
            r.last_seen = now.to_string();
            r.seen = 1;
            st.recs.insert(r.key.clone(), r);
        }
        Some(o) => {
            o.last_seen = now.to_string();
            o.seen += 1;
            if r.rank > o.rank {
                o.rank = r.rank;
                o.verdict = r.verdict.clone();
                o.findings = r.findings.clone();
            }
            if o.path.is_empty() || (!r.path.is_empty() && r.path != o.path && !o.path.contains(&r.path)) {
                o.path = if o.path.is_empty() {
                    r.path.clone()
                } else if o.path.len() < 600 {
                    format!("{} ; {}", o.path, r.path)
                } else {
                    o.path.clone()
                };
            }
            if !r.source.is_empty() && !o.source.contains(&r.source) {
                o.source += " ; ";
                o.source += &r.source;
            }
        }
    }
    st.dirty = true;
}

fn own_rank(r: &ScanResult) -> i32 {
    let mut k = 0;
    for f in &r.findings {
        k = k.max(category_rank(&f.category));
    }
    k
}

fn known_identity(r: &ScanResult) -> bool {
    if r.findings
        .iter()
        .any(|f| f.key == "known_client" || f.key == "client_addon")
    {
        return true;
    }
    r.meta.id.truthy && verified_id(&py_lower(&r.meta.id.s)).is_some()
}

fn walk(st: &mut State, r: &ScanResult, source: &str) -> i32 {
    let mut n = 0;
    let rk = own_rank(r);
    if rk >= 1 && !r.trusted_infra && !r.server_plugin && !known_identity(r) {
        let mut x = LearnRec {
            kind: "jar".to_string(),
            name: r.name.clone(),
            path: r.file.clone(),
            ..Default::default()
        };
        for a in &r.also_at {
            if x.path.len() < 600 {
                x.path += " ; ";
                x.path += a;
            }
        }
        x.source = source.to_string();
        x.rank = rk;
        x.verdict = verdict_by_rank(rk);
        x.sha256 = if r.has_sha { r.sha256.clone() } else { String::new() };
        x.size = r.size;
        x.key = if !x.sha256.is_empty() {
            x.sha256.clone()
        } else {
            format!("ad:{}#{}", py_lower(&r.name), r.size)
        };
        if r.meta.id.truthy {
            x.mod_id = r.meta.id.s.clone();
        }
        if r.meta.name.truthy {
            x.mod_name = r.meta.name.s.clone();
        }
        if r.meta.version.truthy {
            x.version = r.meta.version.s.clone();
        }
        if r.meta.loader.truthy {
            x.loader = r.meta.loader.s.clone();
        }
        x.packages = join(&r.pkg_summary, " ; ");
        let mut mt: StrList = Vec::new();
        for m in &r.mixins {
            for t in &m.targets {
                if mt.len() < 24 && !mt.contains(t) {
                    mt.push(t.clone());
                }
            }
        }
        x.mixins = join(&mt, " ; ");
        let mut fs: StrList = Vec::new();
        for f in &r.findings {
            if category_rank(&f.category) >= 1 {
                fs.push(format!("{}|{}|{}", f.key, f.category, f.label));
            }
        }
        x.findings = join(&fs, " ; ");
        upsert_locked(st, x);
        n += 1;
    }
    if known_identity(r) {
        return n;
    }
    for s in &r.nested {
        n += walk(st, s, source);
    }
    n
}

pub fn learn_load() {
    let mut st = lock();
    load_locked(&mut st);
}
fn source_goster(s: &str) -> String {
    s.replace("Mod Taramasi", "Mod Taraması")
        .replace("Disk Taramasi", "Disk Taraması")
        .replace("Yerel Modul", "Yerel Modül")
}
pub fn learn_path() -> String {
    let mut st = lock();
    load_locked(&mut st);
    st.path.clone()
}

pub fn learn_from_result(r: &ScanResult, source: &str) -> i32 {
    let mut st = lock();
    load_locked(&mut st);
    walk(&mut st, r, source)
}
pub fn learn_from_dll(f: &DllFinding) -> i32 {
    let mut st = lock();
    load_locked(&mut st);
    if f.tag != 'k' && f.tag != 's' {
        return 0;
    }
    let mut all = String::new();
    for l in &f.detail {
        all += l;
        all.push('\n');
    }
    let all_f = katla(&all);
    if all_f.contains("ailesi") || all_f.contains("Hile istemci adi") || all_f.contains("Istemci:") {
        return 0;
    }
    let mut x = LearnRec::default();
    let mem = dll_finding_is_memory(f);
    x.kind = if mem { "bellek" } else { "dll" }.to_string();
    x.name = f.name.clone();
    x.path = if f.path.is_empty() {
        f.r#where.clone()
    } else {
        f.path.clone()
    };
    x.source = if mem { "String Scanner" } else { "DLL / Yerel Modül" }.to_string();
    x.rank = if f.tag == 'k' { 3 } else { 1 };
    x.verdict = f.verdict.clone();
    for l in &f.detail {
        let s = lstrip(l, " |");
        if starts(&s, "SHA-256") {
            if let Some(c) = s.find(':') {
                let v = pystrip(&s[c + 1..]);
                let mut e = v.len().min(64);
                while !v.is_char_boundary(e) {
                    e -= 1;
                }
                x.sha256 = v[..e].to_string();
            }
        } else if starts(&s, "Stringler") && x.packages.is_empty() {
            if let Some(c) = s.find(':') {
                x.packages = format!("bellek stringleri: {}", pystrip(&s[c + 1..]));
            }
        }
    }
    let mut ev: StrList = Vec::new();
    for l in &f.detail {
        let s = pystrip(l);
        if (starts(&s, ": [S")
            || starts(&s, ": [T")
            || starts(&s, ": [H")
            || starts(&katla(&s), "Kanit")
            || starts(&s, "| KARAR"))
            && ev.len() < 10
        {
            ev.push(s);
        }
    }
    x.findings = format!(
        "{}{}",
        if f.reason.is_empty() {
            String::new()
        } else {
            format!("{} ; ", f.reason)
        },
        join(&ev, " ; ")
    );
    if !x.sha256.is_empty() {
        x.key = x.sha256.clone();
    } else {
        let h = sha256_hex(format!("{}|{}", x.name, x.packages).as_bytes());
        x.key = format!("mem:{}", &h[..h.len().min(32)]);
    }
    upsert_locked(&mut st, x);
    1
}

pub fn learn_save() -> bool {
    let mut st = lock();
    load_locked(&mut st);
    if !st.dirty {
        return true;
    }
    let ok = write_file(&st.path, serialize(&st.recs).as_bytes());
    if ok {
        st.dirty = false;
    }
    ok
}

fn records_locked(st: &State) -> Vec<LearnRec> {
    let mut v: Vec<LearnRec> = st.recs.values().cloned().collect();
    v.sort_by(|a, b| b.rank.cmp(&a.rank).then_with(|| b.last_seen.cmp(&a.last_seen)));
    v
}

pub fn learn_records() -> Vec<LearnRec> {
    let mut st = lock();
    load_locked(&mut st);
    records_locked(&st)
}
pub fn learn_count() -> usize {
    let mut st = lock();
    load_locked(&mut st);
    st.recs.len()
}
pub fn learn_export_lines() -> StrList {
    let (v, raw) = {
        let mut st = lock();
        load_locked(&mut st);
        (records_locked(&st), serialize(&st.recs))
    };
    export_lines(&v, &raw, &fmt_dt(Some(now_epoch())))
}

fn export_lines(v: &[LearnRec], raw: &str, now: &str) -> StrList {
    let mut l: StrList = Vec::new();
    let eq = "=".repeat(78);
    let dash = "-".repeat(78);
    l.push(eq.clone());
    l.push("JOURNALSCANNER - YENİ HİLE LİSTESİ (hafıza)".to_string());
    l.push(format!("Tarih: {}   |   Kayıt sayısı: {}", now, v.len()));
    l.push(eq.clone());
    l.push(String::new());
    l.push("Bu listede, imza listemizde OLMAYAN (kimliği tanınmayan) ama DAVRANIŞINDAN hile olarak".to_string());
    l.push("yakalanan dosyalar var: adı, mod kimliği ve paketi bilinmeyen yeni / özel yapım hileler.".to_string());
    l.push(
        "Kimliğiyle zaten tanınan hileler (bilinen client paketi, doğrulanmış mod kimliği) bu listeye girmez."
            .to_string(),
    );
    l.push("Bu dosyayı geliştiriciye gönderin: kimlikleri ve kodlama yapıları imza listesine eklenir.".to_string());
    l.push(String::new());
    if v.is_empty() {
        l.push("Henüz kayıt yok: taramalar kimliği bilinmeyen bir hile bulmadı.".to_string());
        return l;
    }
    let dash_or = |s: &str| if s.is_empty() { "-".to_string() } else { s.to_string() };
    for (i, r) in v.iter().enumerate() {
        l.push(dash.clone());
        l.push(format!("[{}] {}   {}", i + 1, goster_buyuk(&r.verdict), r.name));
        let tur = if r.kind == "jar" {
            "Java mod / jar (kod analiziyle yakalandı)"
        } else if r.kind == "dll" {
            "Yerel modül / DLL"
        } else {
            "Çalışan oyunun belleğinde metin kalıntısı"
        };
        l.push(format!("    Tür          : {}", tur));
        if !r.mod_id.is_empty() || !r.mod_name.is_empty() {
            l.push(format!(
                "    Mod kimliği  : {}   Ad: {}   Sürüm: {}   Yükleyici: {}",
                dash_or(&r.mod_id),
                dash_or(&r.mod_name),
                dash_or(&r.version),
                dash_or(&r.loader)
            ));
        }
        if !r.packages.is_empty() {
            l.push(format!("    Kodlama      : {}", r.packages));
        }
        if !r.mixins.is_empty() {
            l.push(format!("    Mixin hedef. : {}", r.mixins));
        }
        if !r.findings.is_empty() {
            l.push("    Neden hile   :".to_string());
            for f in split(&r.findings, " ; ", -1) {
                let p = split(&f, "|", -1);
                if p.len() >= 3 {
                    l.push(format!(
                        "        - [{}] {}   ({})",
                        replace_all(&p[1], "_", " "),
                        p[2],
                        p[0]
                    ));
                } else if !pystrip(&f).is_empty() {
                    l.push(format!("        - {}", f));
                }
            }
        }
        if !r.sha256.is_empty() {
            l.push(format!("    SHA-256      : {}", r.sha256));
        }
        if r.size != 0 {
            let sz = if r.size >= (1u64 << 20) {
                format!("{:.1} MB", r.size as f64 / 1048576.0)
            } else {
                format!("{:.1} KB", r.size as f64 / 1024.0)
            };
            l.push(format!("    Boyut        : {}", sz));
        }
        l.push(format!("    Konum        : {}", r.path));
        l.push(format!("    Bulan sekme  : {}", source_goster(&r.source)));
        l.push(format!(
            "    Görülme      : {} kez   (ilk: {}   son: {})",
            r.seen, r.first_seen, r.last_seen
        ));
    }
    l.push(dash);
    l.push(String::new());
    l.push(eq.clone());
    l.push("MAKİNE OKUNUR BLOK - bu bölümü de olduğu gibi gönderin (imza listesine eklemek için)".to_string());
    l.push(eq);
    for x in split(raw, "\n", -1) {
        l.push(x);
    }
    l
}

pub fn learn_clear() -> bool {
    let mut st = lock();
    load_locked(&mut st);
    st.recs.clear();
    st.dirty = false;
    write_file(&st.path, serialize(&st.recs).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(key: &str, rank: i32) -> LearnRec {
        LearnRec {
            key: key.to_string(),
            kind: "jar".to_string(),
            name: "x.jar".to_string(),
            path: "C:\\a\\x.jar".to_string(),
            source: "Mod Taraması".to_string(),
            verdict: "SUPHELI".to_string(),
            size: 123,
            rank,
            findings: "k|KAT|etiket".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn roundtrip() {
        let mut st = State::default();
        upsert_at(&mut st, rec("abc", 2), "01.01.2025 10:00:00");
        let mut r2 = rec("def", 1);
        r2.name = "multi\nline".to_string();
        upsert_at(&mut st, r2, "01.01.2025 10:00:01");
        let txt = serialize(&st.recs);
        assert!(txt.starts_with("# JournalScanner HAFIZA"));
        let mut back = BTreeMap::new();
        parse_store(&mut back, &txt.replace('\n', "\r\n"));
        assert_eq!(back.len(), 2);
        assert_eq!(back["abc"].size, 123);
        assert_eq!(back["abc"].seen, 1);
        assert_eq!(back["def"].name, "multi line");
        assert_eq!(serialize(&back), serialize(&st.recs));
    }

    #[test]
    fn merge_rules() {
        let mut st = State::default();
        upsert_at(&mut st, rec("k", 1), "t1");
        let mut b = rec("k", 3);
        b.path = "D:\\b\\x.jar".to_string();
        b.source = "Disk Taraması".to_string();
        b.verdict = "KESIN".to_string();
        b.findings = "yeni".to_string();
        upsert_at(&mut st, b.clone(), "t2");
        upsert_at(&mut st, b, "t3");
        let o = &st.recs["k"];
        assert_eq!(o.seen, 3);
        assert_eq!(o.first_seen, "t1");
        assert_eq!(o.last_seen, "t3");
        assert_eq!(o.rank, 3);
        assert_eq!(o.verdict, "KESIN");
        assert_eq!(o.findings, "yeni");
        assert_eq!(o.path, "C:\\a\\x.jar ; D:\\b\\x.jar");
        assert_eq!(o.source, "Mod Taraması ; Disk Taraması");
        assert!(st.dirty);
    }

    #[test]
    fn parse_garbage() {
        let mut m = BTreeMap::new();
        parse_store(
            &mut m,
            "key=ignored\n[kayit]\nkey=a\nsize=-1\nseen=zz\nnoeq\n#c\n=x\n[kayit]\nname=nokey\n",
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m["a"].size, u64::MAX);
        assert_eq!(m["a"].seen, 0);
        assert_eq!(c_strtoull("99999999999999999999999"), u64::MAX);
    }
}
