use crate::content::{analyze_files, content_lines, ContentVerdict};
use crate::data::{KNOWN_CLIENTS, STRONG_CHEAT_TERMS};
use crate::locations::{recycle_bin_index, recycle_lookup};
use crate::util::*;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

#[derive(Debug, Clone)]
pub struct BrowserHit {
    pub id: String,
    pub kind: String,
    pub browser: String,
    pub profile: String,
    pub title: String,
    pub url: String,
    pub host: String,
    pub file_path: String,
    pub file_exists: bool,
    pub in_recycle: bool,
    pub read_from: String,
    pub when: String,
    pub verdict: String,
    pub tag: char,
    pub reason: String,
    pub detail: Vec<String>,
}
impl Default for BrowserHit {
    fn default() -> Self {
        BrowserHit {
            id: String::new(),
            kind: String::new(),
            browser: String::new(),
            profile: String::new(),
            title: String::new(),
            url: String::new(),
            host: String::new(),
            file_path: String::new(),
            file_exists: false,
            in_recycle: false,
            read_from: String::new(),
            when: String::new(),
            verdict: "BILGI".to_string(),
            tag: 'i',
            reason: String::new(),
            detail: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrowserScan {
    pub ran: bool,
    pub error: String,
    pub browsers: i32,
    pub profiles: i32,
    pub downloads: i32,
    pub visits: i32,
    pub kesin: i32,
    pub yasakli: i32,
    pub supheli: i32,
    pub info: i32,
    pub files_checked: i32,
    pub clean_files: i32,
    pub unreadable: i32,
    pub verdict: String,
    pub hits: Vec<BrowserHit>,
    pub notes: StrList,
    pub errors: StrList,
    pub sources: StrList,
}
impl Default for BrowserScan {
    fn default() -> Self {
        BrowserScan {
            ran: false,
            error: String::new(),
            browsers: 0,
            profiles: 0,
            downloads: 0,
            visits: 0,
            kesin: 0,
            yasakli: 0,
            supheli: 0,
            info: 0,
            files_checked: 0,
            clean_files: 0,
            unreadable: 0,
            verdict: "TEMIZ".to_string(),
            hits: Vec::new(),
            notes: Vec::new(),
            errors: Vec::new(),
            sources: Vec::new(),
        }
    }
}

fn norm_alnum(s: &str) -> String {
    let mut o = String::new();
    for &c in s.as_bytes() {
        if c.is_ascii_uppercase() {
            o.push((c + 32) as char);
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            o.push(c as char);
        }
    }
    o
}

fn cheat_tokens() -> &'static BTreeSet<String> {
    static S: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
        let mut s = BTreeSet::new();
        const DENY: [&str; 11] = [
            "baritone",
            "autototem",
            "freecam",
            "nofall",
            "fullbright",
            "minimap",
            "schematica",
            "optifine",
            "sodium",
            "iris",
            "litematica",
        ];
        for kc in KNOWN_CLIENTS {
            let t = norm_alnum(kc.1);
            if t.len() >= 8 && !DENY.contains(&t.as_str()) {
                s.insert(t);
            }
        }
        for t in STRONG_CHEAT_TERMS {
            let n = norm_alnum(t);
            if n.len() >= 7 {
                s.insert(n);
            }
        }
        for extra in [
            "liquidbounce",
            "wurstclient",
            "meteorclient",
            "sigmaclient",
            "novoline",
            "aristois",
            "rusherhack",
            "thunderhack",
            "futureclient",
            "impactclient",
            "vapeclient",
            "vapev4",
            "nightx",
            "nightware",
            "doomsday",
            "slinky",
            "exhibition",
            "prestige",
            "entropyclient",
            "moonclient",
            "riseclient",
            "zeroday",
            "konasclient",
            "tenacity",
            "fluxclient",
            "astolfo",
            "kamiblue",
            "salhack",
            "lambdaclient",
            "pyroclient",
            "dopeclient",
            "ghostclient",
            "madebygrave",
            "argonclient",
            "cliento",
        ] {
            s.insert(extra.to_string());
        }
        s
    });
    &S
}

fn match_cheat_token(norm: &str) -> String {
    if norm.is_empty() {
        return String::new();
    }
    for t in cheat_tokens() {
        if norm.contains(t.as_str()) {
            return t.clone();
        }
    }
    String::new()
}

fn col_text(row: &rusqlite::Row, i: usize) -> String {
    match row.get_ref(i) {
        Ok(ValueRef::Text(t)) => String::from_utf8_lossy(t).into_owned(),
        Ok(ValueRef::Integer(v)) => v.to_string(),
        Ok(ValueRef::Real(v)) => v.to_string(),
        Ok(ValueRef::Blob(b)) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    }
}

fn col_i64(row: &rusqlite::Row, i: usize) -> i64 {
    match row.get_ref(i) {
        Ok(ValueRef::Integer(v)) => v,
        Ok(ValueRef::Real(v)) => v as i64,
        Ok(ValueRef::Text(t)) => {
            let s = String::from_utf8_lossy(t);
            let s = s.trim_start();
            let end = s
                .char_indices()
                .take_while(|&(k, c)| c.is_ascii_digit() || (k == 0 && (c == '-' || c == '+')))
                .last()
                .map_or(0, |(k, c)| k + c.len_utf8());
            s.get(..end).and_then(|x| x.parse().ok()).unwrap_or(0)
        }
        _ => 0,
    }
}

fn open_ro(path: &str) -> Option<Connection> {
    if let Ok(c) = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        return Some(c);
    }
    let uri = format!("file:{}?immutable=1", path);
    Connection::open_with_flags(&uri, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI).ok()
}

fn has_table(db: &Connection, name: &str) -> bool {
    match db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1") {
        Ok(mut st) => match st.query([name]) {
            Ok(mut rows) => matches!(rows.next(), Ok(Some(_))),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

fn copy_db(src: &str, tmpdir: &str, tag: &str) -> String {
    let d = match read_file(src, -1, 0) {
        Some(d) => d,
        None => return String::new(),
    };
    let dst = path_join(tmpdir, &format!("{}.db", tag));
    if !write_file(&dst, &d) {
        return String::new();
    }
    for suf in ["-wal", "-shm"] {
        if let Some(e) = read_file(&format!("{}{}", src, suf), -1, 0) {
            write_file(&format!("{}{}", dst, suf), &e);
        }
    }
    dst
}

fn chrome_time(micros1601: i64) -> String {
    if micros1601 <= 0 {
        return String::new();
    }
    let unix = micros1601 as f64 / 1e6 - 11644473600.0;
    fmt_dt(Some(unix))
}
fn ff_time(micros1970: i64) -> String {
    if micros1970 <= 0 {
        return String::new();
    }
    fmt_dt(Some(micros1970 as f64 / 1e6))
}
fn chrome_unix(micros1601: i64) -> f64 {
    if micros1601 <= 0 {
        0.0
    } else {
        micros1601 as f64 / 1e6 - 11644473600.0
    }
}
fn ff_unix(micros1970: i64) -> f64 {
    if micros1970 <= 0 {
        0.0
    } else {
        micros1970 as f64 / 1e6
    }
}

fn host_of(url: &str) -> String {
    let a = match url.find("://") {
        Some(p) => p + 3,
        None => 0,
    };
    let rest = url.get(a..).unwrap_or("");
    let e = rest.find(['/', '?', '#']);
    let mut h = match e {
        Some(e) => &rest[..e],
        None => rest,
    };
    if let Some(at) = h.find('@') {
        h = &h[at + 1..];
    }
    if let Some(col) = h.find(':') {
        h = &h[..col];
    }
    h.to_string()
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut o: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(a), Some(c)) = (hexval(b[i + 1]), hexval(b[i + 2])) {
                o.push(a * 16 + c);
                i += 3;
                continue;
            }
        }
        o.push(b[i]);
        i += 1;
    }
    match String::from_utf8(o) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

fn file_uri_to_path(uri: &str) -> String {
    if !starts(uri, "file:") {
        return uri.to_string();
    }
    let p = uri.get(5..).unwrap_or("").trim_start_matches('/');
    let p = url_decode(p);
    if cfg!(windows) {
        p.replace('/', "\\")
    } else {
        format!("/{}", p)
    }
}

#[derive(Default, Clone)]
struct RawDownload {
    url: String,
    path: String,
    when: f64,
    bytes: i64,
    browser: String,
    profile: String,
}
#[derive(Default, Clone)]
struct RawVisit {
    url: String,
    title: String,
    when: f64,
    count: i64,
    browser: String,
    profile: String,
}

fn read_chromium(db: &Connection, dls: &mut Vec<RawDownload>, vis: &mut Vec<RawVisit>) {
    if has_table(db, "downloads") {
        let mut chain: BTreeMap<i64, String> = BTreeMap::new();
        if has_table(db, "downloads_url_chains") {
            if let Ok(mut st) = db.prepare("SELECT id, url FROM downloads_url_chains ORDER BY id, chain_index") {
                if let Ok(mut rows) = st.query([]) {
                    while let Ok(Some(r)) = rows.next() {
                        let id = col_i64(r, 0);
                        chain.entry(id).or_insert_with(|| col_text(r, 1));
                    }
                }
            }
        }
        let mut has_tab = true;
        let mut st =
            match db.prepare("SELECT id, target_path, current_path, start_time, total_bytes, tab_url FROM downloads") {
                Ok(s) => s,
                Err(_) => {
                    has_tab = false;
                    match db.prepare("SELECT id, target_path, current_path, start_time, total_bytes FROM downloads") {
                        Ok(s) => s,
                        Err(_) => return,
                    }
                }
            };
        let qres = st.query([]);
        if let Ok(mut rows) = qres {
            while let Ok(Some(r)) = rows.next() {
                let mut d = RawDownload::default();
                let id = col_i64(r, 0);
                d.path = col_text(r, 1);
                if d.path.is_empty() {
                    d.path = col_text(r, 2);
                }
                d.when = chrome_unix(col_i64(r, 3));
                d.bytes = col_i64(r, 4);
                if let Some(u) = chain.get(&id) {
                    d.url = u.clone();
                } else if has_tab {
                    d.url = col_text(r, 5);
                }
                if !d.path.is_empty() {
                    dls.push(d);
                }
            }
        }
    }
    if has_table(db, "urls") {
        if let Ok(mut st) = db.prepare("SELECT url, title, last_visit_time, visit_count FROM urls") {
            if let Ok(mut rows) = st.query([]) {
                while let Ok(Some(r)) = rows.next() {
                    let v = RawVisit {
                        url: col_text(r, 0),
                        title: col_text(r, 1),
                        when: chrome_unix(col_i64(r, 2)),
                        count: col_i64(r, 3),
                        ..Default::default()
                    };
                    if !v.url.is_empty() {
                        vis.push(v);
                    }
                }
            }
        }
    }
}

fn read_firefox(db: &Connection, dls: &mut Vec<RawDownload>, vis: &mut Vec<RawVisit>) {
    if has_table(db, "moz_annos") && has_table(db, "moz_anno_attributes") && has_table(db, "moz_places") {
        if let Ok(mut st) = db.prepare(
            "SELECT p.url, a.content, a.dateAdded FROM moz_annos a \
             JOIN moz_places p ON p.id=a.place_id \
             JOIN moz_anno_attributes t ON t.id=a.anno_attribute_id \
             WHERE t.name='downloads/destinationFileURI'",
        ) {
            if let Ok(mut rows) = st.query([]) {
                while let Ok(Some(r)) = rows.next() {
                    let d = RawDownload {
                        url: col_text(r, 0),
                        path: file_uri_to_path(&col_text(r, 1)),
                        when: ff_unix(col_i64(r, 2)),
                        ..Default::default()
                    };
                    if !d.path.is_empty() {
                        dls.push(d);
                    }
                }
            }
        }
    }
    if has_table(db, "moz_places") {
        if let Ok(mut st) = db.prepare("SELECT url, title, last_visit_date, visit_count FROM moz_places") {
            if let Ok(mut rows) = st.query([]) {
                while let Ok(Some(r)) = rows.next() {
                    let v = RawVisit {
                        url: col_text(r, 0),
                        title: col_text(r, 1),
                        when: ff_unix(col_i64(r, 2)),
                        count: col_i64(r, 3),
                        ..Default::default()
                    };
                    if !v.url.is_empty() {
                        vis.push(v);
                    }
                }
            }
        }
    }
}

struct Profile {
    browser: String,
    name: String,
    history_db: String,
    firefox: bool,
}

#[cfg(windows)]
fn find_chromium(user_data: &str, browser: &str, out: &mut Vec<Profile>) {
    if !is_dir(user_data) {
        return;
    }
    let mut ents = Vec::new();
    list_dir(user_data, &mut ents);
    for e in &ents {
        if !e.is_dir {
            continue;
        }
        let n = &e.name;
        let prof = n == "Default" || n == "Guest Profile" || starts(n, "Profile ");
        if !prof {
            continue;
        }
        let hist = path_join_all(&[user_data, n, "History"]);
        if is_file(&hist) {
            out.push(Profile {
                browser: browser.to_string(),
                name: n.clone(),
                history_db: hist,
                firefox: false,
            });
        }
    }
}

#[cfg(windows)]
fn find_firefox(profiles_dir: &str, browser: &str, out: &mut Vec<Profile>) {
    if !is_dir(profiles_dir) {
        return;
    }
    let mut ents = Vec::new();
    list_dir(profiles_dir, &mut ents);
    for e in &ents {
        if !e.is_dir {
            continue;
        }
        let places = path_join_all(&[profiles_dir, &e.name, "places.sqlite"]);
        if is_file(&places) {
            out.push(Profile {
                browser: browser.to_string(),
                name: e.name.clone(),
                history_db: places,
                firefox: true,
            });
        }
    }
}

#[cfg(windows)]
fn discover_profiles() -> Vec<Profile> {
    let mut out = Vec::new();
    let local = env("LOCALAPPDATA");
    let roaming = env("APPDATA");
    const CHROMIUM: [(&str, &str); 9] = [
        ("Google\\Chrome\\User Data", "Chrome"),
        ("Microsoft\\Edge\\User Data", "Edge"),
        ("BraveSoftware\\Brave-Browser\\User Data", "Brave"),
        ("Chromium\\User Data", "Chromium"),
        ("Vivaldi\\User Data", "Vivaldi"),
        ("Yandex\\YandexBrowser\\User Data", "Yandex"),
        ("Opera Software\\Opera Stable", "Opera"),
        ("Opera Software\\Opera GX Stable", "Opera GX"),
        ("Google\\Chrome SxS\\User Data", "Chrome Canary"),
    ];
    for (sub, name) in CHROMIUM {
        if local.is_empty() {
            break;
        }
        let base = path_join(&local, sub);
        let hist = path_join(&base, "History");
        if is_file(&hist) {
            out.push(Profile {
                browser: name.to_string(),
                name: "Default".to_string(),
                history_db: hist,
                firefox: false,
            });
        }
        find_chromium(&base, name, &mut out);
    }
    const FFS: [(&str, &str, bool); 3] = [
        ("Mozilla\\Firefox\\Profiles", "Firefox", true),
        ("librewolf\\Profiles", "LibreWolf", true),
        ("Waterfox\\Profiles", "Waterfox", true),
    ];
    for (sub, name, use_roaming) in FFS {
        let b = if use_roaming { &roaming } else { &local };
        if b.is_empty() {
            continue;
        }
        find_firefox(&path_join(b, sub), name, &mut out);
    }
    out
}

fn discover_from_env() -> Vec<Profile> {
    let mut out = Vec::new();
    let split_paths = |v: &str| -> StrList {
        split(v, ";", -1)
            .iter()
            .filter(|p| !strip(p, WS_CHARS).is_empty())
            .map(|p| strip(p, WS_CHARS))
            .collect()
    };
    for ud in split_paths(&env("JS_BROWSER_CHROMIUM")) {
        let hist = path_join(&ud, "History");
        if is_file(&hist) {
            out.push(Profile {
                browser: "Chromium(test)".to_string(),
                name: "Default".to_string(),
                history_db: hist,
                firefox: false,
            });
        }
        if is_dir(&ud) {
            let mut ents = Vec::new();
            list_dir(&ud, &mut ents);
            for e in &ents {
                if !e.is_dir {
                    continue;
                }
                let hist = path_join_all(&[&ud, &e.name, "History"]);
                if is_file(&hist) {
                    out.push(Profile {
                        browser: "Chromium(test)".to_string(),
                        name: e.name.clone(),
                        history_db: hist,
                        firefox: false,
                    });
                }
            }
        }
    }
    for pd in split_paths(&env("JS_BROWSER_FIREFOX")) {
        if is_dir(&pd) {
            let mut ents = Vec::new();
            list_dir(&pd, &mut ents);
            for e in &ents {
                if !e.is_dir {
                    continue;
                }
                let places = path_join_all(&[&pd, &e.name, "places.sqlite"]);
                if is_file(&places) {
                    out.push(Profile {
                        browser: "Firefox(test)".to_string(),
                        name: e.name.clone(),
                        history_db: places,
                        firefox: true,
                    });
                }
            }
        }
    }
    out
}

fn rank_tag_b(r: i32) -> char {
    if r >= 3 {
        'k'
    } else if r == 2 {
        'y'
    } else if r == 1 {
        's'
    } else {
        't'
    }
}

fn tag_order(t: char) -> i32 {
    match t {
        'k' => 0,
        'y' => 1,
        's' => 2,
        _ => 3,
    }
}

pub fn scan_browsers(days: i32, progress: Option<StrProgress>, stop: Option<&StopFlag>) -> BrowserScan {
    let mut s = BrowserScan::default();
    #[allow(unused_mut)]
    let mut profiles = discover_from_env();
    #[cfg(windows)]
    profiles.extend(discover_profiles());
    if profiles.is_empty() {
        s.ran = true;
        s.notes.push(
            "Cihazda okunabilir tarayıcı geçmişi bulunamadı (Chrome/Edge/Brave/Opera/Vivaldi/Firefox ...).".to_string(),
        );
        return s;
    }
    let stopped = || stop.is_some_and(|f| f.is_set());
    let say = |m: &str| {
        if let Some(p) = progress {
            p(m);
        }
    };
    let mut seen_browser: BTreeSet<String> = BTreeSet::new();
    let cutoff = if days > 0 {
        now_epoch() - days as f64 * 86400.0
    } else {
        0.0
    };
    let tmp = make_temp_dir("jsbrow");

    let mut downloads: Vec<RawDownload> = Vec::new();
    let mut visits: BTreeMap<String, RawVisit> = BTreeMap::new(); // url -> en güncel
    for (pidx, pr) in profiles.iter().enumerate() {
        if stopped() {
            break;
        }
        s.profiles += 1;
        seen_browser.insert(pr.browser.clone());
        s.sources.push(format!("{} / {}", pr.browser, pr.name));
        say(&format!("Tarayıcı geçmişi okunuyor: {} / {}", pr.browser, pr.name));
        let copy = copy_db(&pr.history_db, &tmp, &format!("p{}", pidx));
        if copy.is_empty() {
            s.errors
                .push(format!("{}/{}: geçmiş dosyası okunamadı", pr.browser, pr.name));
            continue;
        }
        let mut dls: Vec<RawDownload> = Vec::new();
        let mut vs: Vec<RawVisit> = Vec::new();
        {
            let db = match open_ro(&copy) {
                Some(d) => d,
                None => {
                    s.errors
                        .push(format!("{}/{}: geçmiş veritabanı açılamadı", pr.browser, pr.name));
                    continue;
                }
            };
            if pr.firefox {
                read_firefox(&db, &mut dls, &mut vs);
            } else {
                read_chromium(&db, &mut dls, &mut vs);
            }
        }
        s.downloads += dls.len() as i32;
        s.visits += vs.len() as i32;
        for mut d in dls {
            if cutoff != 0.0 && d.when != 0.0 && d.when < cutoff {
                continue;
            }
            d.browser = pr.browser.clone();
            d.profile = pr.name.clone();
            downloads.push(d);
        }
        for mut v in vs {
            if cutoff != 0.0 && v.when != 0.0 && v.when < cutoff {
                continue;
            }
            let newer = match visits.get(&v.url) {
                None => true,
                Some(old) => v.when > old.when,
            };
            if newer {
                v.browser = pr.browser.clone();
                v.profile = pr.name.clone();
                visits.insert(v.url.clone(), v);
            }
        }
    }

    s.browsers = seen_browser.len() as i32;

    say("Silinmiş indirmeler için Geri Dönüşüm Kutusu okunuyor...");
    let rbin = recycle_bin_index();
    let mut dlhits: Vec<BrowserHit> = Vec::new();
    let mut to_read: StrList = Vec::new();
    for d in &downloads {
        let mut h = BrowserHit {
            kind: "indirme".to_string(),
            browser: d.browser.clone(),
            profile: d.profile.clone(),
            url: d.url.clone(),
            host: host_of(&d.url),
            file_path: d.path.clone(),
            when: if d.when != 0.0 {
                fmt_dt(Some(d.when))
            } else {
                String::new()
            },
            file_exists: is_file(&d.path),
            title: path_basename(&replace_all(&d.path, "\\", "/")),
            ..Default::default()
        };
        if h.file_exists {
            h.read_from = d.path.clone();
        } else {
            let r = recycle_lookup(&rbin, &d.path);
            if !r.is_empty() {
                h.in_recycle = true;
                h.read_from = r;
            }
        }
        if !h.read_from.is_empty() {
            to_read.push(h.read_from.clone());
        }
        dlhits.push(h);
    }

    let content = analyze_files(&to_read, stop, progress);

    for h in dlhits.iter_mut() {
        if stopped() {
            break;
        }
        let tokn = match_cheat_token(&norm_alnum(&h.title));
        let tokh = match_cheat_token(&norm_alnum(&h.host));
        let where_ = if h.file_exists {
            "  (cihazda VAR)"
        } else if h.in_recycle {
            "  (SİLİNMİŞ - Geri Dönüşüm Kutusu'nda bulundu)"
        } else {
            "  (cihazda YOK)"
        };
        let mut head: StrList = vec![
            format!("  Tarayıcı : {} / {}", h.browser, h.profile),
            format!(
                "  Kaynak   : {}{}",
                if h.url.is_empty() { "-" } else { &h.url },
                if h.host.is_empty() {
                    String::new()
                } else {
                    format!("   (site: {})", h.host)
                }
            ),
            format!("  İndirildi: {}", if h.when.is_empty() { "-" } else { &h.when }),
            format!("  Dosya    : {}{}", h.file_path, where_),
        ];
        if h.in_recycle {
            head.push(format!("  Okunan   : {}", h.read_from));
        }
        let tok_any = if tokh.is_empty() { &tokn } else { &tokh };

        let mut c: Option<&ContentVerdict> = None;
        if !h.read_from.is_empty() {
            if let Some(cv) = content.get(&py_lower(&h.read_from)) {
                if cv.readable {
                    c = Some(cv);
                }
            }
        }
        if let Some(c) = c {
            s.files_checked += 1;
            if c.rank > 0 {
                h.verdict = c.verdict.clone();
                h.tag = rank_tag_b(c.rank);
                h.reason = format!(
                    "İndirilen dosyanın İÇERİĞİ kod analiz motoruyla okundu: {}",
                    goster_buyuk(&h.verdict)
                );
                h.detail = vec![format!("[{}]  {}", goster_buyuk(&h.verdict), h.title)];
                h.detail.extend(head.iter().cloned());
                h.detail.push(
                    "  Karar    : Dosyanın İÇERİĞİ JournalScanner kod analiz motoruyla okundu (mod bytecode / arşiv /"
                        .to_string(),
                );
                h.detail.push(
                    "             PE / kaynak kod). Dosya ADI, UZANTISI ve indirildiği SİTE karara KATILMADI."
                        .to_string(),
                );
                h.detail.push(String::new());
                h.detail.extend(content_lines(c));
                s.hits.push(h.clone());
            } else {
                s.clean_files += 1;
                if !tokn.is_empty() || !tokh.is_empty() {
                    h.verdict = "BILGI".to_string();
                    h.tag = 'i';
                    h.reason = format!(
                        "İçerik okundu: hile kodu YOK (temiz). Ad/site bilinen hile adıyla eşleşiyor ({})",
                        tok_any
                    );
                    h.detail = vec![format!("[BİLGİ - içerik TEMİZ]  {}", h.title)];
                    h.detail.extend(head.iter().cloned());
                    h.detail.push("  Sonuç    : Dosyanın içeriği kod analiz motoruyla okundu, hile / yasaklı işlev kodu BULUNAMADI.".to_string());
                    h.detail.push(format!(
                        "  Not      : Ad ya da site bilinen bir hile adıyla eşleşiyor ({}); bu tek başına hile KANITI değildir, karar içerikten verildi (TEMIZ).",
                        tok_any
                    ));
                    s.hits.push(h.clone());
                }
            }
        } else {
            s.unreadable += 1;
            if !tokn.is_empty() || !tokh.is_empty() {
                h.verdict = "BILGI".to_string();
                h.tag = 'i';
                h.reason = format!(
                    "Dosya cihazda yok, içerik okunamadı -> karar verilmedi (ad/site: {})",
                    tok_any
                );
                h.detail = vec![format!("[BİLGİ - içerik OKUNAMADI]  {}", h.title)];
                h.detail.extend(head.iter().cloned());
                h.detail.push(
                    "  Sonuç    : Dosya cihazda da Geri Dönüşüm Kutusu'nda da yok; içeriği okunamadığı için"
                        .to_string(),
                );
                h.detail
                    .push("             hile karari VERİLMEDİ (yalnızca içerikten karar verilir).".to_string());
                h.detail.push(format!(
                    "  Not      : İndirme kaydı tarayıcıda duruyor; ad/site bilinen hile adıyla eşleşiyor ({}). Dosya silinmiş / taşınmış olabilir.",
                    tok_any
                ));
                s.hits.push(h.clone());
            }
        }
    }

    let mut host_done: BTreeSet<String> = BTreeSet::new();
    for v in visits.values() {
        if stopped() {
            break;
        }
        let host = host_of(&v.url);
        let tok = match_cheat_token(&norm_alnum(&host));
        if tok.is_empty() {
            continue;
        }
        if !host_done.insert(py_lower(&host)) {
            continue;
        }
        let mut h = BrowserHit {
            kind: "ziyaret".to_string(),
            browser: v.browser.clone(),
            profile: v.profile.clone(),
            host: host.clone(),
            url: v.url.clone(),
            title: format!(
                "{}{}",
                host,
                if v.title.is_empty() {
                    String::new()
                } else {
                    format!("  -  {}", uslice(&v.title, 60))
                }
            ),
            when: if v.when != 0.0 {
                fmt_dt(Some(v.when))
            } else {
                String::new()
            },
            verdict: "BILGI".to_string(),
            tag: 'i',
            reason: format!("Bilinen hile istemcisi sitesi ziyaret edilmiş ({})", tok),
            ..Default::default()
        };
        let lh = py_lower(&host);
        let dl_from = dlhits.iter().filter(|d| py_lower(&d.host) == lh).count();
        h.detail = vec![
            format!("[BİLGİ - site ziyareti]  {}", host),
            format!("  Tarayıcı : {} / {}", h.browser, h.profile),
            format!("  Adres    : {}", v.url),
            format!("  Son ziyaret: {}", if h.when.is_empty() { "-" } else { &h.when }),
            format!("  Ziyaret  : {} kez", v.count),
            format!("  Eşleşme  : {}", tok),
            format!("  Bu siteden indirme kaydı: {}", dl_from),
            "  Not      : Ziyaret tek başına hile KANITI değildir. Bu siteden indirilen dosyalar varsa".to_string(),
            "             içerikleri yukarıda kod analiz motoruyla okunup ayrı karar verildi.".to_string(),
        ];
        s.hits.push(h);
    }

    for h in &s.hits {
        match h.tag {
            'k' => s.kesin += 1,
            'y' => s.yasakli += 1,
            's' => s.supheli += 1,
            _ => s.info += 1,
        }
    }
    s.hits.sort_by(|a, b| {
        tag_order(a.tag)
            .cmp(&tag_order(b.tag))
            .then_with(|| a.kind.cmp(&b.kind)) // "indirme" < "ziyaret"
    });
    for (n, h) in s.hits.iter_mut().enumerate() {
        h.id = format!("h{}", n);
    }
    s.verdict = if s.kesin > 0 {
        "KESIN HILE"
    } else if s.yasakli > 0 {
        "YASAKLI ISLEV"
    } else if s.supheli > 0 {
        "SUPHELI"
    } else {
        "TEMIZ"
    }
    .to_string();
    s.ran = true;
    remove_tree(&tmp);
    s
}

pub fn browser_hit_lines(h: &BrowserHit) -> Vec<String> {
    if !h.detail.is_empty() {
        return h.detail.clone();
    }
    vec![
        format!("[{}]  {}", goster_buyuk(&h.verdict), h.title),
        format!("  {}", h.reason),
    ]
}

pub fn browser_overview_lines(s: &BrowserScan) -> Vec<String> {
    let mut l: Vec<String> = vec![
        "TARAYICI GEÇMİŞİ (indirme + site)".to_string(),
        "=".repeat(70),
        String::new(),
    ];
    if !s.ran && !s.error.is_empty() {
        l.push(format!("[HATA] {}", s.error));
        return l;
    }
    l.push(format!(
        "Taranan: {} tarayıcı, {} profil  |  {} indirme kaydı, {} site kaydı",
        s.browsers, s.profiles, s.downloads, s.visits
    ));
    l.push(format!(
        "İndirilen dosyalardan {} tanesinin İÇERİĞİ kod analiz motoruyla okundu: {} temiz, {} hile/yasaklı/şüpheli.",
        s.files_checked,
        s.clean_files,
        s.kesin + s.yasakli + s.supheli
    ));
    if s.unreadable != 0 {
        l.push(format!(
            "{} indirmenin dosyası cihazda / Geri Dönüşüm Kutusu'nda yok (içerik okunamadı, karar verilmedi).",
            s.unreadable
        ));
    }
    l.push("Karar YALNIZCA dosya içeriğine göre verilir; dosya adı, uzantı ve site karara katılmaz.".to_string());
    l.push(String::new());
    if s.kesin + s.yasakli + s.supheli == 0 {
        l.push("İndirilen dosyaların içeriğinde hile / yasaklı işlev BULUNAMADI.".to_string());
    } else {
        l.push(format!(
            "GENEL KARAR: {}   (kesin {}, yasaklı {}, şüpheli {})",
            s.verdict, s.kesin, s.yasakli, s.supheli
        ));
    }
    if s.info != 0 {
        l.push(format!(
            "Bilgi satırı: {} (hile sitesi ziyareti / içeriği okunamayan ya da temiz çıkan hile adli indirme)",
            s.info
        ));
    }
    if !s.sources.is_empty() {
        l.push(String::new());
        l.push("Taranan tarayıcı/profiller:".to_string());
        for x in &s.sources {
            l.push(format!("  - {}", x));
        }
    }
    for n in &s.notes {
        l.push(String::new());
        l.push(n.clone());
    }
    for e in &s.errors {
        l.push(format!("  [!] {}", e));
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_cikarma() {
        assert_eq!(host_of("https://user:pw@Example.com:8080/a?b#c"), "Example.com");
        assert_eq!(host_of("example.org/x"), "example.org");
        assert_eq!(host_of("http://a.b?x=1"), "a.b");
        assert_eq!(host_of(""), "");
    }

    #[test]
    fn url_cozme() {
        assert_eq!(url_decode("a%20b%2Fc"), "a b/c");
        assert_eq!(url_decode("100%"), "100%");
        assert_eq!(url_decode("%zz1"), "%zz1");
        assert_eq!(url_decode("x%41"), "xA");
        assert_eq!(url_decode("x%41y"), "xAy");
    }

    #[test]
    fn dosya_uri() {
        assert_eq!(file_uri_to_path("C:\\x"), "C:\\x");
        if cfg!(windows) {
            assert_eq!(
                file_uri_to_path("file:///C:/Users/a%20b/x.jar"),
                "C:\\Users\\a b\\x.jar"
            );
        }
    }

    #[test]
    fn norm() {
        assert_eq!(norm_alnum("Meteor Client_1.jar"), "meteorclient1jar");
    }

    #[test]
    fn zaman() {
        assert_eq!(chrome_unix(0), 0.0);
        assert_eq!(chrome_unix(11644473600 * 1_000_000), 0.0 + 0.0);
        assert_eq!(ff_unix(2_000_000), 2.0);
    }

    #[test]
    fn sqlite_okuma() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE urls(url TEXT, title TEXT, last_visit_time INTEGER, visit_count INTEGER);\
             INSERT INTO urls VALUES('https://a.b/', NULL, 13300000000000000, 3);",
        )
        .unwrap();
        assert!(has_table(&db, "urls"));
        assert!(!has_table(&db, "downloads"));
        let mut dls = Vec::new();
        let mut vis = Vec::new();
        read_chromium(&db, &mut dls, &mut vis);
        assert!(dls.is_empty());
        assert_eq!(vis.len(), 1);
        assert_eq!(vis[0].title, "");
        assert_eq!(vis[0].count, 3);
    }
}
