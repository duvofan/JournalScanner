use crate::data::{VerifiedId, VERIFIED_IDS};
use crate::disk::ResultP;
use crate::jar::{category_rank, scan_jar, verdict_by_rank, ScanResult};
use crate::json::{jget, read_json_bytes};
use crate::rx::Rx;
use crate::util::*;
use crate::zipr::{gunzip, ZipReader};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

#[derive(Debug, Clone, Default)]
pub struct LogMod {
    pub id: String,
    pub version: String,
    pub raw: String,
    pub source: String,
    pub path: String,
    pub file: String,
    pub sha1: String,
    pub line: i32,
    pub nested: bool,
    pub fresh: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct ForgeLoaded {
    pub fp: String,
    pub line: i32,
    pub raw: String,
}

#[derive(Debug, Clone, Default)]
pub struct LogInfo {
    pub mods: BTreeMap<String, LogMod>,
    pub loader: Option<String>,
    pub mc: Option<String>,
    pub user: Option<String>,
    pub servers: StrList,
    pub singleplayer: bool,
    pub forge_files: StrList,
    pub forge_loaded: Vec<ForgeLoaded>,
    pub lines: usize,
}

pub type ResultSP = Arc<ScanResult>;

#[derive(Debug, Clone, Default)]
pub struct LogHit {
    pub r#mod: LogMod,
    pub jar: String,
    pub code: Option<ResultSP>,
    pub known: Option<&'static VerifiedId>,
    pub basis: String,
    pub same: bool,
    pub category: String,
}

#[derive(Debug, Clone, Default)]
pub struct LogResult {
    pub file: String,
    pub name: String,
    pub dir: String,
    pub mtime: f64,
    pub size: u64,
    pub rank: i32,
    pub verdict: String,
    pub info: LogInfo,
    pub hits: Vec<LogHit>,
    pub same_session: StrList,
    pub mods_total: usize,
}

#[derive(Debug, Clone, Default)]
pub struct LogFileInfo {
    pub file: String,
    pub mtime: f64,
    pub size: u64,
    pub mods: usize,
    pub loader: Option<String>,
    pub user: Option<String>,
    pub servers: StrList,
}

#[derive(Debug, Clone)]
pub struct LogScan {
    pub dirs: StrList,
    pub files: Vec<LogFileInfo>,
    pub results: Vec<LogResult>,
    pub errors: StrList,
    pub days: i32,
    pub duration: f64,
    pub cutoff: f64,
    pub jars_checked: usize,
}
impl Default for LogScan {
    fn default() -> Self {
        LogScan {
            dirs: Vec::new(),
            files: Vec::new(),
            results: Vec::new(),
            errors: Vec::new(),
            days: 5,
            duration: 0.0,
            cutoff: 0.0,
            jars_checked: 0,
        }
    }
}

const MAX_LOG_BYTES: u64 = 96 * 1024 * 1024;

macro_rules! rx_static {
    ($name:ident, $pat:expr) => {
        rx_static!($name, $pat, 0);
    };
    ($name:ident, $pat:expr, $flags:expr) => {
        fn $name() -> &'static Rx {
            static R: LazyLock<Rx> = LazyLock::new(|| Rx::new($pat, $flags));
            &R
        }
    };
}

rx_static!(
    r_ts,
    r"^\[(\d{2}:\d{2}:\d{2})\]|^\[(\d{2}[A-Za-z]{3}\d{4} \d{2}:\d{2}:\d{2}\.\d+)\]|^\[\d"
);
rx_static!(
    r_fabric_hdr,
    r"^\[[^\]]+\] \[main/(?:INFO|DEBUG)\](?: \([^)]*\))?:? (?:\[FabricLoader\] |\[QuiltLoader\] )?Loading (\d+) mods?:\s*(.*)$"
);
rx_static!(
    r_fabric_item,
    r"^[\t ]*(?:\|[\t ]+)*(?:-|\|--|\\--)[\t ]+([A-Za-z0-9_.\-]+)[\t ]+(\S+)"
);
rx_static!(r_fabric_old, r"([A-Za-z0-9_.\-]+)@(\S+?)(?:,|$)");
rx_static!(
    r_forge_valid,
    r"Found valid mod file (.+?) with \{([^}]*)\} mods - versions \{([^}]*)\}"
);
rx_static!(r_forge_cand, r"Considering mod file candidate (.+\.jar)\s*$", Rx::I);
rx_static!(
    r_forge_found,
    r"Found mod file (.+?) of type (\w+) with provider \{?mods folder locator at (.+?)\}?\s*$"
);
rx_static!(
    r_forge_modlist,
    r"^\s+(\S.*?\.jar)\s*\|([^|]*)\|\s*([A-Za-z0-9_.\-]+)\s*\|\s*([^|]+?)\s*\|"
);
rx_static!(r_modlist_hdr, r"^\s*(?:-- )?Mod List(?: --)?:?\s*$|^\s*Mod List:\s*$");
rx_static!(
    r_loader,
    r"Loading Minecraft (\S+) with (Fabric Loader|Quilt Loader) (\S+)"
);
rx_static!(
    r_forge_ver,
    r"(?:Forge|NeoForge) (?:mod loader )?version (\S+)|--fml\.(?:forge|neoForge)Version, (\S+?)[,\]]"
);
rx_static!(
    r_mc_ver,
    r"--fml\.mcVersion, (\S+?)[,\]]|Minecraft Version: (\S+)|Loading Minecraft (\S+)"
);
rx_static!(r_user, r"Setting user: (\S+)|--username, (\S+?)[,\]]");
rx_static!(r_connect, r"Connecting to ([^,\s]+), ?(\d+)");
rx_static!(
    r_sp,
    r"Starting integrated minecraft server version|Preparing start region for dimension"
);
rx_static!(r_date_name, r"(\d{4})-(\d{2})-(\d{2})");
rx_static!(r_mf_impl, r"^Implementation-Version:\s*(\S+)", Rx::M);
rx_static!(r_toml_modid, r##"modId\s*=\s*"([^"]+)""##);
rx_static!(r_toml_ver, r##"version\s*=\s*"([^"]+)""##);

pub fn verified_id(id: &str) -> Option<&'static VerifiedId> {
    static M: LazyLock<HashMap<&'static str, &'static VerifiedId>> =
        LazyLock::new(|| VERIFIED_IDS.iter().map(|v| (v.id, v)).collect());
    M.get(id).copied()
}

pub fn launcher_roots() -> StrList {
    let mut appdata = env("APPDATA");
    if appdata.is_empty() {
        appdata = path_join_all(&[&home_dir(), "AppData", "Roaming"]);
    }
    let mut home = env("USERPROFILE");
    if home.is_empty() {
        home = home_dir();
    }
    let mut c: StrList = Vec::new();
    for n in [
        ".minecraft",
        ".tlauncher",
        ".feather",
        "PrismLauncher",
        "MultiMC",
        "PolyMC",
        "ModrinthApp",
        "com.modrinth.theseus",
        "ATLauncher",
        "gdlauncher_next",
        "gdlauncher_carbon",
        ".technic",
        "Badlion Client",
    ] {
        c.push(path_join(&appdata, n));
    }
    for n in [".minecraft", ".lunarclient"] {
        c.push(path_join(&home, n));
    }
    c.push(path_join_all(&[&home, "curseforge", "minecraft", "Instances"]));
    for x in split(&env("JS_LAUNCHER_ROOTS"), ";", -1) {
        if !strip(&x, WS_CHARS).is_empty() {
            c.push(strip(&x, WS_CHARS));
        }
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for r in c {
        if is_dir(&r) && seen.insert(path_norm(&r)) {
            out.push(r);
        }
    }
    out
}

fn skip_walk_dir(low: &str) -> bool {
    matches!(
        low,
        "assets"
            | "libraries"
            | "saves"
            | "resourcepacks"
            | "shaderpacks"
            | "screenshots"
            | "natives"
            | "jre"
            | "runtime"
            | "cache"
            | ".git"
            | "node_modules"
            | "crash-reports"
            | "backups"
            | "replay_recordings"
            | ".cache"
            | "texturepacks"
    )
}

fn find_named_dirs(root: &str, name: &str, depth: i32, out: &mut StrList, budget: &mut i32) {
    if depth < 0 || *budget <= 0 {
        return;
    }
    let mut ents = Vec::new();
    if !list_dir(root, &mut ents) {
        return;
    }
    for e in &ents {
        if !e.is_dir || e.reparse || e.is_link {
            continue;
        }
        *budget -= 1;
        if *budget <= 0 {
            return;
        }
        let low = py_lower(&e.name);
        if low == name {
            out.push(e.path.clone());
            continue;
        }
        if skip_walk_dir(&low) {
            continue;
        }
        find_named_dirs(&e.path, name, depth - 1, out, budget);
    }
}

fn dir_has_ext(d: &str, ext: &str) -> bool {
    let mut ents = Vec::new();
    if !list_dir(d, &mut ents) {
        return false;
    }
    ents.iter().any(|e| e.is_file && ends(&py_lower(&e.name), ext))
}

fn is_game_instance_dir(d: &str) -> bool {
    is_file(&path_join(d, "options.txt")) || is_dir(&path_join(d, "config")) || is_dir(&path_join(d, "saves"))
}

pub fn auto_mod_dirs(primary: &str) -> StrList {
    let mut found = Vec::new();
    let mut budget = 20000;
    for r in launcher_roots() {
        find_named_dirs(&r, "mods", 6, &mut found, &mut budget);
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    if !primary.is_empty() {
        seen.insert(path_norm(primary));
    }
    for d in found {
        if !dir_has_ext(&d, ".jar") {
            continue;
        }
        if !is_game_instance_dir(&path_dirname(&d)) {
            continue;
        }
        if seen.insert(path_norm(&d)) {
            out.push(d);
        }
    }
    out
}

pub fn launcher_log_dirs() -> StrList {
    let mut found = Vec::new();
    let mut budget = 20000;
    for r in launcher_roots() {
        find_named_dirs(&r, "logs", 6, &mut found, &mut budget);
    }
    let mut out = Vec::new();
    for d in found {
        if dir_has_ext(&d, ".log") || dir_has_ext(&d, ".log.gz") {
            out.push(d.clone());
        }
        let mut ents = Vec::new(); // örnek: .lunarclient\logs\game
        if !list_dir(&d, &mut ents) {
            continue;
        }
        for e in &ents {
            if e.is_dir && !e.reparse && (dir_has_ext(&e.path, ".log") || dir_has_ext(&e.path, ".log.gz")) {
                out.push(e.path.clone());
            }
        }
    }
    out
}

pub fn log_dirs(extra_mods_dir: &str) -> StrList {
    let mut out = Vec::new();
    let mut appdata = env("APPDATA");
    if appdata.is_empty() {
        appdata = path_join_all(&[&home_dir(), "AppData", "Roaming"]);
    }
    let mut home = env("USERPROFILE");
    if home.is_empty() {
        home = home_dir();
    }
    let mut cands: StrList = vec![
        path_join_all(&[&appdata, ".minecraft", "logs"]),
        path_join_all(&[&appdata, ".tlauncher", "legacy", "Minecraft", "game", "logs"]),
        path_join_all(&[&home, ".minecraft", "logs"]),
    ];
    if !extra_mods_dir.is_empty() {
        cands.push(path_join(&path_dirname(&path_normpath(extra_mods_dir)), "logs"));
    }
    let inst: StrList = vec![
        path_join_all(&[&home, "curseforge", "minecraft", "Instances"]),
        path_join_all(&[&appdata, "PrismLauncher", "instances"]),
        path_join_all(&[&appdata, "MultiMC", "instances"]),
        path_join_all(&[&appdata, "ModrinthApp", "profiles"]),
        path_join_all(&[&appdata, "com.modrinth.theseus", "profiles"]),
        path_join_all(&[&appdata, "ATLauncher", "instances"]),
        path_join_all(&[&appdata, "gdlauncher_next", "instances"]),
        path_join_all(&[&appdata, ".tlauncher", "legacy", "Minecraft", "game", "versions"]),
    ];
    for root in &inst {
        let mut ents = Vec::new();
        if !list_dir(root, &mut ents) {
            continue;
        }
        for e in &ents {
            let base = &e.path;
            for sub in [
                "logs".to_string(),
                path_join(".minecraft", "logs"),
                path_join("minecraft", "logs"),
            ] {
                cands.push(path_join(base, &sub));
            }
        }
    }
    for d in launcher_log_dirs() {
        cands.push(d);
    }
    let mut seen = BTreeSet::new();
    for c in cands {
        if !is_dir(&c) {
            continue;
        }
        let k = path_norm(&c);
        if seen.insert(k) {
            out.push(c);
        }
    }
    out
}

struct RecentLog {
    p: String,
    when: f64,
    size: u64,
}

fn recent_logs(d: &str, cutoff: f64) -> Vec<RecentLog> {
    let mut out = Vec::new();
    let mut ents = Vec::new();
    if !list_dir(d, &mut ents) {
        return out;
    }
    for e in &ents {
        let low = py_lower(&e.name);
        if !(ends(&low, ".log") || ends(&low, ".log.gz")) {
            continue;
        }
        if !e.is_file {
            continue;
        }
        let mut when = e.mtime;
        if let Some(m) = r_date_name().search(e.name.as_bytes(), 0) {
            let y: i32 = m.group(1).parse().unwrap_or(0);
            let mo: i32 = m.group(2).parse().unwrap_or(0);
            let dd: i32 = m.group(3).parse().unwrap_or(0);
            if (1..=12).contains(&mo) && (1..=31).contains(&dd) && y >= 1 {
                when = when.min(local_mktime(y, mo, dd, 23, 59, 59));
            }
        }
        if when >= cutoff {
            out.push(RecentLog {
                p: e.path.clone(),
                when,
                size: e.size,
            });
        }
    }
    out
}

fn read_log(p: &str) -> Result<String, &'static str> {
    let is_gz = ends(&py_lower(p), ".gz");
    let raw = match read_file(p, if is_gz { -1 } else { MAX_LOG_BYTES as i64 }, 0) {
        Some(r) => r,
        None => return Err("dosya okunamadı"),
    };
    let data: Bytes = if is_gz {
        let mut data = Vec::new();
        let mut complete = false;
        let ok = gunzip(&raw, &mut data, MAX_LOG_BYTES, Some(&mut complete));
        if !ok && data.is_empty() {
            return Err("gzip açılamadı");
        }
        data
    } else {
        raw
    };
    if data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]) {
        return Ok(utf16_auto(&data, 0));
    }
    if utf8_valid(&data, false) {
        Ok(String::from_utf8(data).unwrap_or_else(|e| utf8_decode(e.as_bytes(), 0)))
    } else {
        Ok(cp1254_to_utf8(&data))
    }
}

fn strip_l(s: &str) -> String {
    pystrip(s)
}

fn add_mod(info: &mut LogInfo, mid: &str, ver: &str, ln: i32, raw: &str, src: &str, path: &str, nested: bool) {
    let mid = py_lower(&strip_l(mid));
    if mid.is_empty()
        || matches!(
            mid.as_str(),
            "java" | "minecraft" | "fabricloader" | "quilt_loader" | "forge" | "neoforge" | "fml"
        )
    {
        return;
    }
    match info.mods.get_mut(&mid) {
        None => {
            let mut shown = strip_l(raw);
            if has(&shown, "]: ") && starts(&shown, "[") {
                shown = rpartition_tail(&shown, "]: ");
            }
            let m = LogMod {
                id: mid.clone(),
                version: strip_l(ver),
                line: ln,
                raw: uslice(&shown, 200),
                source: src.to_string(),
                path: path.to_string(),
                nested,
                ..Default::default()
            };
            info.mods.insert(mid, m);
        }
        Some(m) => {
            if !path.is_empty() && m.path.is_empty() {
                m.path = path.to_string();
            }
        }
    }
}

pub fn parse_log(text: &str) -> LogInfo {
    let mut info = LogInfo::default();
    let lines = splitlines(text);
    info.lines = lines.len();
    let n = lines.len();
    let mut i = 0usize;
    let mut in_modlist = false;
    while i < n {
        let ln: &str = &lines[i];
        let lnb = ln.as_bytes();
        if has(ln, "[CHAT]") || has(ln, "[Not Secure]") {
            i += 1;
            in_modlist = false;
            continue;
        }
        if let Some(m) = r_fabric_hdr().match_(lnb, 0) {
            let rest = strip_l(&m.group(2));
            if !rest.is_empty() && has(&rest, "@") {
                r_fabric_old().finditer(rest.as_bytes(), &mut |mm| {
                    add_mod(
                        &mut info,
                        &mm.group(1),
                        &mm.group(2),
                        i as i32 + 1,
                        ln,
                        "Fabric yükleyici mod listesi",
                        "",
                        false,
                    );
                    true
                });
                i += 1;
                continue;
            }
            let mut j = i + 1;
            let mut have_cols = false;
            let mut cols: BTreeMap<String, usize> = BTreeMap::new();
            while j < n && r_ts().match_(lines[j].as_bytes(), 0).is_none() {
                let row: &str = &lines[j];
                if starts(&lstrip(row, WS_CHARS), "|") {
                    let inner = strip(&strip_l(row), "|");
                    let cells: Vec<String> = split(&inner, "|", -1).iter().map(|c| strip_l(c)).collect();
                    let has_id = cells.iter().any(|c| py_lower(c) == "id");
                    let mut first_sep = true;
                    if let Some(c0) = cells.first() {
                        if c0.chars().any(|ch| ch != '-' && ch != ':') {
                            first_sep = false;
                        }
                    }
                    if !have_cols && has_id {
                        have_cols = true;
                        for (k, c) in cells.iter().enumerate() {
                            cols.insert(py_lower(c), k);
                        }
                    } else if have_cols && !cols.is_empty() && !cells.is_empty() && !first_sep {
                        let g = |k: &str| -> i64 { cols.get(k).map_or(-1, |&v| v as i64) };
                        let ci = g("id");
                        let cv = g("version");
                        let mut cf = g("file(s)");
                        let ch = g("file hash (sha-1)");
                        if cf <= 0 {
                            cf = g("file");
                        }
                        let cell = |x: i64| -> Option<&String> {
                            if x >= 0 {
                                cells.get(x as usize)
                            } else {
                                None
                            }
                        };
                        if let Some(idc) = cell(ci) {
                            add_mod(
                                &mut info,
                                idc,
                                cell(cv).map_or("?", |s| s.as_str()),
                                j as i32 + 1,
                                row,
                                "Quilt yükleyici mod tablosu",
                                cell(cf).map_or("", |s| s.as_str()),
                                false,
                            );
                            if let Some(e) = info.mods.get_mut(&py_lower(&strip_l(idc))) {
                                if let Some(h) = cell(ch) {
                                    if is_hex40(h) {
                                        e.sha1 = lower_ascii(h);
                                    }
                                }
                            }
                        }
                    }
                } else if let Some(mm) = r_fabric_item().match_(row.as_bytes(), 0) {
                    add_mod(
                        &mut info,
                        &mm.group(1),
                        &mm.group(2),
                        j as i32 + 1,
                        row,
                        "Fabric yükleyici mod listesi",
                        "",
                        has(row, "|--") || has(row, "\\--"),
                    );
                }
                j += 1;
            }
            i = j;
            continue;
        }
        let forge_logger = has(ln, "moddiscovery") || has(ln, "ModFileParser") || has(ln, "ModDiscoverer");
        if forge_logger {
            if let Some(mv) = r_forge_valid().search(lnb, 0) {
                let ids: Vec<String> = split(&mv.group(2), ",", -1)
                    .iter()
                    .filter(|x| !strip_l(x).is_empty())
                    .map(|x| strip_l(x))
                    .collect();
                let vers: Vec<String> = split(&mv.group(3), ",", -1).iter().map(|x| strip_l(x)).collect();
                for (k, idk) in ids.iter().enumerate() {
                    add_mod(
                        &mut info,
                        idk,
                        vers.get(k).map_or("?", |s| s.as_str()),
                        i as i32 + 1,
                        ln,
                        "Forge/NeoForge mod doğrulama kaydı",
                        "",
                        false,
                    );
                    if let Some(e) = info.mods.get_mut(&py_lower(idk)) {
                        e.file = strip_l(&mv.group(1));
                    }
                }
            }
            if let Some(mc) = r_forge_cand().search(lnb, 0) {
                info.forge_files.push(strip_l(&mc.group(1)));
            }
            if let Some(mf) = r_forge_found().search(lnb, 0) {
                if upper_ascii(&mf.group(2)) == "MOD" {
                    let fp = path_join(&strip_l(&mf.group(3)), &strip_l(&mf.group(1)));
                    info.forge_files.push(fp.clone());
                    info.forge_loaded.push(ForgeLoaded {
                        fp,
                        line: i as i32 + 1,
                        raw: uslice(&rpartition_tail(ln, "]: "), 200),
                    });
                }
            }
        }
        if r_modlist_hdr().match_(lnb, 0).is_some() {
            in_modlist = true;
            i += 1;
            continue;
        }
        if in_modlist {
            if r_ts().match_(lnb, 0).is_some() || strip_l(ln).is_empty() {
                in_modlist = false;
            } else if let Some(ml) = r_forge_modlist().match_(lnb, 0) {
                add_mod(
                    &mut info,
                    &ml.group(3),
                    &ml.group(4),
                    i as i32 + 1,
                    ln,
                    "Forge mod listesi (hata raporu bölümü)",
                    "",
                    false,
                );
                if let Some(e) = info.mods.get_mut(&py_lower(&ml.group(3))) {
                    e.file = strip_l(&ml.group(1));
                }
            }
        }
        if info.loader.is_none() {
            if let Some(ml2) = r_loader().search(lnb, 0) {
                info.mc = Some(ml2.group(1));
                info.loader = Some(format!("{} {}", ml2.group(2), ml2.group(3)));
            } else if let Some(mfv) = r_forge_ver().search(lnb, 0) {
                let pre = if has(&py_lower(ln), "neo") {
                    "NeoForge "
                } else {
                    "Forge "
                };
                let v = if mfv.ok(1) { mfv.group(1) } else { mfv.group(2) };
                info.loader = Some(format!("{}{}", pre, v));
            }
        }
        if info.mc.is_none() {
            if let Some(mm) = r_mc_ver().search(lnb, 0) {
                info.mc = Some(if mm.ok(1) {
                    mm.group(1)
                } else if mm.ok(2) {
                    mm.group(2)
                } else {
                    mm.group(3)
                });
            }
        }
        let ts = r_ts().match_(lnb, 0).is_some();
        if info.user.is_none() && ts {
            if let Some(mu) = r_user().search(lnb, 0) {
                info.user = Some(if mu.ok(1) { mu.group(1) } else { mu.group(2) });
            }
        }
        if ts {
            if let Some(mcn) = r_connect().search(lnb, 0) {
                if has(ln, "Server Connector") || has(ln, "Render thread") {
                    let s = format!("{}:{}", mcn.group(1), mcn.group(2));
                    if !info.servers.contains(&s) {
                        info.servers.push(s);
                    }
                }
            }
        }
        if !info.singleplayer && r_sp().search(lnb, 0).is_some() {
            info.singleplayer = true;
        }
        i += 1;
    }
    info
}

pub fn jar_meta(path: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let data = match read_file(path, -1, 0) {
        Some(d) => d,
        None => return out,
    };
    let mut z = ZipReader::new();
    if !z.open(&data) {
        return out;
    }
    let getf = |n: &str| -> Option<Bytes> {
        let e = z.entries().iter().rev().find(|x| x.name == n)?;
        let mut b = Vec::new();
        if z.read(e, &mut b, None, None, 1u64 << 34) {
            Some(b)
        } else {
            None
        }
    };
    for n in ["fabric.mod.json", "quilt.mod.json"] {
        let b = match getf(n) {
            Some(b) => b,
            None => continue,
        };
        let j = match read_json_bytes(&b) {
            Some(j) => j,
            None => continue,
        };
        if !j.is_obj() {
            return Vec::new(); // Python: AttributeError -> []
        }
        if n == "quilt.mod.json" {
            let q = j.get("quilt_loader");
            if let Some(q) = q {
                if !q.is_obj() {
                    return Vec::new();
                }
            }
            let id = jget(q, "id");
            let ver = jget(q, "version");
            out.push((
                py_lower(&id.map_or(String::new(), |v| v.py_str())),
                ver.map_or(String::new(), |v| v.py_str()),
            ));
        } else {
            let id = j.get("id");
            let ver = j.get("version");
            out.push((
                py_lower(&id.map_or(String::new(), |v| v.py_str())),
                ver.map_or(String::new(), |v| v.py_str()),
            ));
        }
    }
    let mut impl_ver = String::new();
    if let Some(mf) = getf("META-INF/MANIFEST.MF") {
        if let Some(m) = r_mf_impl().search(utf8_decode(&mf, 1).as_bytes(), 0) {
            impl_ver = m.group(1);
        }
    }
    for n in ["META-INF/mods.toml", "META-INF/neoforge.mods.toml"] {
        let b = match getf(n) {
            Some(b) => b,
            None => continue,
        };
        let t = utf8_decode(&b, 1);
        let blocks = split(&t, "[[mods]]", -1);
        for blk in blocks.iter().skip(1) {
            if let Some(mi) = r_toml_modid().search(blk.as_bytes(), 0) {
                let mut v = r_toml_ver()
                    .search(blk.as_bytes(), 0)
                    .map(|mv| mv.group(1))
                    .unwrap_or_default();
                if v == "${file.jarVersion}" {
                    v = impl_ver.clone();
                }
                out.push((py_lower(&mi.group(1)), v));
            }
        }
    }
    out
}

type JarVers = BTreeMap<String, Vec<(String, String)>>;

#[derive(Default)]
struct JarIndex {
    by_folder: BTreeMap<String, JarVers>,
    sha1_by_folder: BTreeMap<String, BTreeMap<String, String>>,
}

impl JarIndex {
    fn folder(&mut self, d: &str) -> &JarVers {
        let k = path_norm(d);
        self.by_folder.entry(k).or_insert_with(|| {
            let mut idx: JarVers = BTreeMap::new();
            let mut ents = Vec::new();
            if list_dir(d, &mut ents) {
                ents.sort_by(|a, b| a.name.cmp(&b.name));
                for e in &ents {
                    if !e.is_file {
                        continue;
                    }
                    match read_file(&e.path, 4, 0) {
                        Some(h) if h == b"PK\x03\x04" => {}
                        _ => continue,
                    }
                    for (id, ver) in jar_meta(&e.path) {
                        if !id.is_empty() {
                            idx.entry(id).or_default().push((ver, e.path.clone()));
                        }
                    }
                }
            }
            idx
        })
    }
    fn sha1(&mut self, d: &str) -> &BTreeMap<String, String> {
        let k = path_norm(d);
        if !self.sha1_by_folder.contains_key(&k) {
            let mut out = BTreeMap::new();
            for vl in self.folder(d).values() {
                for vp in vl {
                    if let Some(b) = read_file(&vp.1, -1, 0) {
                        out.insert(sha1_hex(&b), vp.1.clone());
                    }
                }
            }
            self.sha1_by_folder.insert(k.clone(), out);
        }
        self.sha1_by_folder.entry(k).or_default()
    }
}

fn resolve_jar(m: &LogMod, info: &LogInfo, folders: &[String], jidx: &mut JarIndex) -> (String, bool) {
    if let Some(f) = m.fresh {
        if !m.path.is_empty() && is_file(&m.path) {
            return (m.path.clone(), f);
        }
    }
    let mut cand: StrList = Vec::new();
    if !m.path.is_empty() {
        cand.push(m.path.clone());
    }
    if !m.file.is_empty() {
        for fp in &info.forge_files {
            if path_basename(fp) == m.file {
                cand.push(fp.clone());
            }
        }
    }
    for cp in &cand {
        if cp.is_empty() || !is_file(cp) {
            continue;
        }
        for iv in jar_meta(cp) {
            if iv.0 == m.id {
                return (cp.clone(), iv.1 == m.version);
            }
        }
    }
    if !m.sha1.is_empty() {
        for fo in folders {
            if let Some(p) = jidx.sha1(fo).get(&m.sha1) {
                return (p.clone(), true);
            }
        }
    }
    let mut other = String::new();
    for fo in folders {
        if let Some(vl) = jidx.folder(fo).get(&m.id) {
            for vp in vl {
                if vp.0 == m.version {
                    return (vp.1.clone(), true);
                }
                if other.is_empty() {
                    other = vp.1.clone();
                }
            }
        }
    }
    (other, false)
}

fn cat_of_rank(r: i32) -> &'static str {
    if r >= 3 {
        "KESIN_HILE"
    } else if r == 2 {
        "YASAKLI_ISLEV"
    } else {
        "SUPHELI"
    }
}

struct Parsed {
    d: String,
    p: String,
    mt: f64,
    sz: u64,
    info: LogInfo,
}
struct PlanRow {
    m: LogMod,
    jar: String,
    same: bool,
}

pub fn scan_logs(
    days: i32,
    extra_mods_dir: &str,
    dirs: Option<&[String]>,
    progress: Option<ProgressFn>,
    now: f64,
) -> LogScan {
    let t0 = now_epoch();
    let now = if now <= 0.0 { now_epoch() } else { now };
    let mut out = LogScan {
        days,
        cutoff: now - days as f64 * 86400.0,
        ..Default::default()
    };
    out.dirs = match dirs {
        Some(d) => d.to_vec(),
        None => log_dirs(extra_mods_dir),
    };
    let mut jidx = JarIndex::default();
    struct FileRec {
        d: String,
        p: String,
        mt: f64,
        sz: u64,
    }
    let mut files: Vec<FileRec> = Vec::new();
    for d in &out.dirs {
        for r in recent_logs(d, out.cutoff) {
            files.push(FileRec {
                d: d.clone(),
                p: r.p,
                mt: r.when,
                sz: r.size,
            });
        }
    }
    files.sort_by(|a, b| {
        a.d.cmp(&b.d)
            .then_with(|| b.mt.partial_cmp(&a.mt).unwrap_or(std::cmp::Ordering::Equal))
    });
    let mut parsed: Vec<Parsed> = Vec::new();
    let total = files.len();
    for (k, f) in files.into_iter().enumerate() {
        if let Some(pg) = progress {
            pg(k as i32 + 1, total as i32, &path_basename(&f.p));
        }
        let text = match read_log(&f.p) {
            Ok(t) => t,
            Err(err) => {
                out.errors.push(format!("{}: okunamadı ({})", f.p, err));
                continue;
            }
        };
        let info = parse_log(&text);
        out.files.push(LogFileInfo {
            file: f.p.clone(),
            mtime: f.mt,
            size: f.sz,
            mods: info.mods.len(),
            loader: info.loader.clone(),
            user: info.user.clone(),
            servers: info.servers.clone(),
        });
        if !info.mods.is_empty() || !info.forge_loaded.is_empty() {
            parsed.push(Parsed {
                d: f.d,
                p: f.p,
                mt: f.mt,
                sz: f.sz,
                info,
            });
        }
    }
    for pr in parsed.iter_mut() {
        let fls = pr.info.forge_loaded.clone();
        for fl in &fls {
            if !is_file(&fl.fp) {
                continue;
            }
            let mt = match file_mtime(&fl.fp) {
                Some(m) => m,
                None => continue,
            };
            let fresh = mt <= pr.mt + 60.0;
            for (jid, jver) in jar_meta(&fl.fp) {
                if !jid.is_empty()
                    && !pr.info.mods.contains_key(&jid)
                    && jid != "forge"
                    && jid != "neoforge"
                    && jid != "minecraft"
                {
                    let m = LogMod {
                        id: jid.clone(),
                        version: if jver.is_empty() { "?".to_string() } else { jver },
                        line: fl.line,
                        raw: fl.raw.clone(),
                        source: "Forge yüklenen mod dosyası kaydı".to_string(),
                        path: fl.fp.clone(),
                        fresh: Some(fresh),
                        ..Default::default()
                    };
                    pr.info.mods.insert(jid, m);
                }
            }
        }
    }
    parsed.retain(|p| !p.info.mods.is_empty());
    let mut plan: Vec<(usize, Vec<PlanRow>)> = Vec::new();
    let mut need: BTreeMap<String, String> = BTreeMap::new(); // norm -> gerçek yol
    for (k, pr) in parsed.iter().enumerate() {
        let mut folders: StrList = Vec::new();
        let md = path_join(&path_dirname(&path_normpath(&pr.d)), "mods");
        if is_dir(&md) {
            folders.push(md);
        }
        let mut rows = Vec::new();
        for (key, lm) in &pr.info.mods {
            let (jar, same) = resolve_jar(lm, &pr.info, &folders, &mut jidx);
            if !jar.is_empty() && (same || verified_id(key).is_some()) {
                need.insert(path_norm(&jar), jar.clone());
            }
            rows.push(PlanRow {
                m: lm.clone(),
                jar,
                same,
            });
        }
        plan.push((k, rows));
    }
    let paths: Vec<String> = need.values().cloned().collect();
    let codes: Mutex<Vec<Option<ResultSP>>> = Mutex::new(vec![None; paths.len()]);
    {
        let next = AtomicUsize::new(0);
        let nt = (cpu_count() as usize).clamp(1, 8);
        std::thread::scope(|s| {
            for _ in 0..nt.min(paths.len()) {
                let _ = std::thread::Builder::new()
                    .stack_size(16 << 20)
                    .spawn_scoped(s, || loop {
                        let i = next.fetch_add(1, Ordering::SeqCst);
                        if i >= paths.len() {
                            break;
                        }
                        let r = Arc::new(scan_jar(&paths[i]));
                        if let Ok(mut g) = codes.lock() {
                            g[i] = Some(r);
                        }
                    });
            }
        });
    }
    let codes = codes.into_inner().unwrap_or_default();
    let mut code_of: BTreeMap<String, ResultSP> = BTreeMap::new();
    for (i, p) in paths.iter().enumerate() {
        if let Some(Some(c)) = codes.get(i) {
            code_of.insert(path_norm(p), c.clone());
        }
    }
    out.jars_checked = paths.len();
    let mut sessions: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, rows) in plan {
        let pr = &parsed[idx];
        let mut hits: Vec<LogHit> = Vec::new();
        for row in rows {
            let mut code: Option<ResultSP> = None;
            if !row.jar.is_empty() {
                code = code_of.get(&path_norm(&row.jar)).cloned();
            }
            let known = verified_id(&row.m.id);
            if let Some(c) = &code {
                if row.same && c.verdict != "OKUNAMADI" {
                    if c.rank >= 2 {
                        let mut cat = String::new();
                        let mut best = -1;
                        for f in &c.findings {
                            let r = category_rank(&f.category);
                            if r > best {
                                best = r;
                                cat = f.category.clone();
                            }
                        }
                        if cat.is_empty() || category_rank(&cat) < c.rank {
                            cat = cat_of_rank(c.rank).to_string();
                        }
                        hits.push(LogHit {
                            r#mod: row.m,
                            jar: row.jar,
                            code: code.clone(),
                            known,
                            basis: "kod".to_string(),
                            same: true,
                            category: cat,
                        });
                    }
                    continue;
                }
            }
            if let Some(k) = known {
                hits.push(LogHit {
                    r#mod: row.m,
                    jar: row.jar,
                    code,
                    known,
                    basis: "kimlik".to_string(),
                    same: row.same,
                    category: k.category.to_string(),
                });
            }
        }
        if hits.is_empty() {
            continue;
        }
        let mut mv: StrList = pr
            .info
            .mods
            .values()
            .map(|m| format!("{}\x1f{}", m.id, m.version))
            .collect();
        mv.sort();
        let skey = format!(
            "{}\x1e{}\x1e{}\x1e{}",
            path_normcase(&pr.d),
            join(&mv, "\x1d"),
            pr.info.user.as_deref().unwrap_or("\x01"),
            join(&pr.info.servers, "\x1d")
        );
        if let Some(&si) = sessions.get(&skey) {
            if let Some(r) = out.results.get_mut(si) {
                r.same_session.push(pr.p.clone());
            }
            continue;
        }
        let rank = hits.iter().map(|h| category_rank(&h.category)).fold(0, i32::max);
        let res = LogResult {
            file: pr.p.clone(),
            name: path_basename(&pr.p),
            dir: pr.d.clone(),
            mtime: pr.mt,
            size: pr.sz,
            rank,
            verdict: verdict_by_rank(rank),
            info: pr.info.clone(),
            hits,
            same_session: Vec::new(),
            mods_total: pr.info.mods.len(),
        };
        sessions.insert(skey, out.results.len());
        out.results.push(res);
    }
    out.results.sort_by(|a, b| {
        b.rank
            .cmp(&a.rank)
            .then_with(|| b.mtime.partial_cmp(&a.mtime).unwrap_or(std::cmp::Ordering::Equal))
    });
    out.duration = now_epoch() - t0;
    out
}

pub fn log_rank(lr: &LogScan) -> i32 {
    lr.results.iter().map(|x| x.rank).fold(0, i32::max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_id_arama() {
        assert!(verified_id("meteor-client").is_some());
        assert!(verified_id("yok-böyle-bir-şey").is_none());
    }

    #[test]
    fn cat_rank() {
        assert_eq!(cat_of_rank(3), "KESIN_HILE");
        assert_eq!(cat_of_rank(2), "YASAKLI_ISLEV");
        assert_eq!(cat_of_rank(0), "SUPHELI");
    }

    #[test]
    fn skip_dirs() {
        assert!(skip_walk_dir("saves"));
        assert!(!skip_walk_dir("mods"));
    }

    #[test]
    fn add_mod_filtreler() {
        let mut info = LogInfo::default();
        add_mod(&mut info, " Minecraft ", "1", 1, "x", "k", "", false);
        assert!(info.mods.is_empty());
        add_mod(&mut info, " Sodium ", " 0.5 ", 3, "[a]: raw satır", "k", "", false);
        let m = &info.mods["sodium"];
        assert_eq!(m.version, "0.5");
        assert_eq!(m.raw, "raw satır");
        add_mod(&mut info, "sodium", "9", 4, "y", "k", "p.jar", false);
        assert_eq!(info.mods["sodium"].path, "p.jar");
        assert_eq!(info.mods["sodium"].version, "0.5");
    }

    #[test]
    fn parse_log_fabric_eski() {
        let t = "[12:00:00] [main/INFO]: Loading 2 mods: sodium@0.5.0, lithium@0.11,\n[12:00:01] [Render thread/INFO]: Setting user: Foo\n";
        let i = parse_log(t);
        assert_eq!(i.mods.len(), 2);
        assert_eq!(i.user.as_deref(), Some("Foo"));
    }
}
