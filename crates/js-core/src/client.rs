use crate::disk::{DiskScanner, ResultP};
use crate::jar::*;
use crate::json::{json_parse, jstr, jtruthy, load_json_file, JPtr};
use crate::logs::*;
use crate::prefetch::*;
use crate::rx::Rx;
use crate::util::*;
use crate::zipr::{zip_opens, ZipReader};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

pub use crate::procs::{list_processes, window_titles};

#[cfg(windows)]
const PATHSEP: &str = ";";
#[cfg(not(windows))]
const PATHSEP: &str = ":";

#[derive(Debug, Clone, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: String,
    pub cmdline: String,
    pub argv: StrList,
    pub created: Option<f64>,
}

pub fn split_cmdline(s: &str) -> StrList {
    let c: Vec<char> = s.chars().collect();
    let n = c.len();
    let mut args: StrList = Vec::new();
    let mut cur = String::new();
    let mut i = 0usize;
    let mut in_q = false;
    let mut have = false;
    while i < n {
        let ch = c[i];
        if ch == '\\' {
            let mut j = i;
            while j < n && c[j] == '\\' {
                j += 1;
            }
            let nb = j - i;
            if j < n && c[j] == '"' {
                for _ in 0..nb / 2 {
                    cur.push('\\');
                }
                if nb % 2 == 1 {
                    cur.push('"');
                    i = j + 1;
                } else {
                    i = j;
                }
                have = true;
                continue;
            }
            for _ in 0..nb {
                cur.push('\\');
            }
            i = j;
            have = true;
            continue;
        }
        if ch == '"' {
            if in_q && i + 1 < n && c[i + 1] == '"' {
                cur.push('"');
                i += 2;
                continue;
            }
            in_q = !in_q;
            have = true;
            i += 1;
            continue;
        }
        if (ch == ' ' || ch == '\t') && !in_q {
            if have || !cur.is_empty() {
                args.push(std::mem::take(&mut cur));
                have = false;
            }
            i += 1;
            continue;
        }
        cur.push(ch);
        have = true;
        i += 1;
    }
    if have || !cur.is_empty() {
        args.push(cur);
    }
    args
}

const SECRET_KEYS: [&str; 8] = [
    "--accesstoken",
    "--session",
    "--clientid",
    "--xuid",
    "--msaaccesstoken",
    "--auth_access_token",
    "--authaccesstoken",
    "--token",
];

fn secret_rx() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx::new("accesstoken|access_token|sessionid", 0))
}

fn split1(s: &str, sep: &str, n: usize) -> String {
    split(s, sep, 1).get(n).cloned().unwrap_or_default()
}

pub fn redact(argv: &[String]) -> StrList {
    let r = secret_rx();
    let mut out: StrList = Vec::new();
    let mut hide = false;
    for a in argv {
        if hide {
            out.push("***".to_string());
            hide = false;
            continue;
        }
        let low = py_lower(a);
        let secret = SECRET_KEYS.iter().any(|k| low == *k);
        if secret {
            out.push(a.clone());
            hide = true;
            continue;
        }
        if has(a, "=") {
            let key = lstrip(&split1(&low, "=", 0), "-");
            let sk = SECRET_KEYS.iter().any(|k| lstrip(k, "-") == key);
            if sk || r.search(low.as_bytes(), 0).is_some() {
                out.push(split1(a, "=", 0) + "=***");
                continue;
            }
        }
        out.push(a.clone());
    }
    out
}

fn expand_argfiles(argv: &[String]) -> StrList {
    let mut out: StrList = Vec::new();
    for a in argv {
        if starts(a, "@") && a.len() > 1 {
            let p = &a[1..];
            let sz = file_size(p);
            if is_file(p) && sz.is_some_and(|s| s < 2_000_000) {
                if let Some(d) = read_file(p, -1, 0) {
                    let mut lines: StrList = Vec::new();
                    for ln in splitlines(&utf8_decode(&d, 0)) {
                        let t = pystrip(&ln);
                        if starts(&t, "#") {
                            continue;
                        }
                        lines.push(t);
                    }
                    for x in split_cmdline(&join(&lines, " ")) {
                        out.push(x);
                    }
                    continue;
                }
            }
        }
        out.push(a.clone());
    }
    out
}

fn cp_paths(v: &str) -> StrList {
    let mut o: StrList = Vec::new();
    for x in split(v, PATHSEP, -1) {
        if !pystrip(&x).is_empty() {
            o.push(x);
        }
    }
    o
}

#[derive(Debug, Clone, Default)]
pub struct JavaAgent {
    pub path: String,
    pub options: String,
}

#[derive(Debug, Clone, Default)]
pub struct JavaCmd {
    pub exe: String,
    pub props: Vec<(String, String)>,
    pub cp: StrList,
    pub module_path: StrList,
    pub bootcp: StrList,
    pub extra_paths: StrList,
    pub jvm_flags: StrList,
    pub game_args: StrList,
    pub agents: Vec<JavaAgent>,
    pub agentpaths: Vec<JavaAgent>,
    pub main: String,
    pub jar: String,
}
impl JavaCmd {
    pub fn prop(&self, k: &str) -> String {
        let mut v = String::new();
        for kv in &self.props {
            if kv.0 == k {
                v = kv.1.clone();
            }
        }
        v
    }
    pub fn has_prop(&self, k: &str) -> bool {
        self.props.iter().any(|kv| kv.0 == k)
    }
}

fn kv_split(s: &str) -> (String, String) {
    match s.find('=') {
        Some(e) => (s[..e].to_string(), s[e + 1..].to_string()),
        None => (s.to_string(), String::new()),
    }
}

pub fn parse_java_cmdline(argv: &[String]) -> JavaCmd {
    const WITH_VALUE: [&str; 13] = [
        "-cp",
        "-classpath",
        "--class-path",
        "-p",
        "--module-path",
        "--add-modules",
        "--add-opens",
        "--add-exports",
        "--add-reads",
        "--patch-module",
        "--upgrade-module-path",
        "--limit-modules",
        "-splash",
    ];
    let mut r = JavaCmd {
        exe: argv.first().cloned().unwrap_or_default(),
        ..Default::default()
    };
    let n = argv.len();
    let mut i = 1usize;
    while i < n {
        let a = argv[i].as_str();
        if a == "-cp" || a == "-classpath" || a == "--class-path" {
            if i + 1 < n {
                r.cp.extend(cp_paths(&argv[i + 1]));
            }
            i += 2;
            continue;
        }
        if a == "-p" || a == "--module-path" {
            if i + 1 < n {
                r.module_path.extend(cp_paths(&argv[i + 1]));
            }
            i += 2;
            continue;
        }
        if starts(a, "--class-path=") || starts(a, "--module-path=") {
            let v = cp_paths(&split1(a, "=", 1));
            if starts(a, "--class-path=") {
                r.cp.extend(v);
            } else {
                r.module_path.extend(v);
            }
            i += 1;
            continue;
        }
        if WITH_VALUE.contains(&a) {
            i += 2;
            continue;
        }
        if starts(a, "-D") {
            let (k, v) = kv_split(&a[2..]);
            r.props.push((k, v));
            i += 1;
            continue;
        }
        if starts(a, "-javaagent:") {
            let (p, o) = kv_split(&a[11..]);
            r.agents.push(JavaAgent { path: p, options: o });
            i += 1;
            continue;
        }
        if starts(a, "-agentpath:") {
            let (p, o) = kv_split(&a[11..]);
            r.agentpaths.push(JavaAgent { path: p, options: o });
            i += 1;
            continue;
        }
        if starts(a, "-agentlib:") {
            r.jvm_flags.push(a.to_string());
            i += 1;
            continue;
        }
        if starts(a, "-Xbootclasspath/a:") || starts(a, "-Xbootclasspath/p:") || starts(a, "-Xbootclasspath:") {
            r.bootcp.extend(cp_paths(&split1(a, ":", 1)));
            i += 1;
            continue;
        }
        if a == "-jar" {
            if i + 1 < n {
                r.jar = argv[i + 1].clone();
                r.game_args = argv.get(i + 2..).unwrap_or(&[]).to_vec();
            }
            break;
        }
        if starts(a, "-") {
            r.jvm_flags.push(a.to_string());
            i += 1;
            continue;
        }
        r.main = a.to_string();
        r.game_args = argv.get(i + 1..).unwrap_or(&[]).to_vec();
        break;
    }
    for key in ["legacyClassPath", "fabric.gameJarPath", "fabric.addMods"] {
        let v = r.prop(key);
        if !v.is_empty() {
            r.extra_paths.extend(cp_paths(&v));
        }
    }
    r
}

fn game_arg(args: &[String], name: &str) -> String {
    for i in 0..args.len() {
        if args[i] == name && i + 1 < args.len() {
            return args[i + 1].clone();
        }
        if starts(&args[i], &format!("{name}=")) {
            return split1(&args[i], "=", 1);
        }
    }
    String::new()
}
fn game_args_multi(args: &[String], name: &str) -> StrList {
    let mut o: StrList = Vec::new();
    for i in 0..args.len() {
        if args[i] == name && i + 1 < args.len() {
            o.push(args[i + 1].clone());
        }
    }
    o
}

const MAIN_CLASSES: [(&str, &str); 12] = [
    ("net.minecraft.client.main.Main", "Vanilla (resmi giriş sınıfı)"),
    ("net.fabricmc.loader.impl.launch.knot.KnotClient", "Fabric"),
    ("net.fabricmc.loader.launch.knot.KnotClient", "Fabric (eski)"),
    ("org.quiltmc.loader.impl.launch.knot.KnotClient", "Quilt"),
    (
        "cpw.mods.bootstraplauncher.BootstrapLauncher",
        "Forge / NeoForge (BootstrapLauncher)",
    ),
    ("cpw.mods.modlauncher.Launcher", "Forge (ModLauncher 1.13-1.16)"),
    ("net.minecraftforge.bootstrap.ForgeBootstrap", "Forge (1.20.3+)"),
    (
        "net.minecraft.launchwrapper.Launch",
        "LaunchWrapper (Forge 1.12 ve öncesi / OptiFine / LiteLoader)",
    ),
    ("com.moonsworth.lunar.genesis.Genesis", "Lunar Client"),
    ("org.prismlauncher.EntryPoint", "Prism Launcher sarmalayıcısı"),
    ("org.multimc.EntryPoint", "MultiMC sarmalayıcısı"),
    ("org.polymc.EntryPoint", "PolyMC sarmalayıcısı"),
];
fn main_class_name(m: &str) -> String {
    for kv in MAIN_CLASSES.iter() {
        if kv.0 == m {
            return kv.1.to_string();
        }
    }
    String::new()
}

pub fn launcher_name(text: &str) -> String {
    static L: OnceLock<Vec<(Rx, &'static str)>> = OnceLock::new();
    let l = L.get_or_init(|| {
        let add = |rx: &str, nm: &'static str| (Rx::new(rx, 0), nm);
        vec![
            add(
                r"minecraftlauncher\.exe$|\\minecraft launcher\\|microsoft\.4297127d64ec6",
                "Resmi Minecraft Launcher",
            ),
            add("tlauncher", "TLauncher"),
            add("sklauncher", "SKLauncher"),
            add("prismlauncher", "Prism Launcher"),
            add("multimc", "MultiMC"),
            add("polymc", "PolyMC"),
            add("curseforge", "CurseForge"),
            add("modrinth|theseus", "Modrinth App"),
            add("atlauncher", "ATLauncher"),
            add("gdlauncher", "GDLauncher"),
            add("lunar client|lunarclient", "Lunar Client"),
            add("badlion", "Badlion Client"),
            add("feather", "Feather Client"),
            add("labymod", "LabyMod Launcher"),
            add("legacylauncher|legacy launcher", "Legacy Launcher"),
            add("salwyrr", "Salwyrr Launcher"),
            add("technic", "Technic Launcher"),
            add("ftb", "FTB App"),
        ]
    });
    let low = py_lower(text);
    for kv in l {
        if kv.0.search(low.as_bytes(), 0).is_some() {
            return kv.1.to_string();
        }
    }
    String::new()
}

pub fn is_minecraft_cmdline(argv: &[String]) -> bool {
    const MARKS: [&str; 13] = [
        "--gamedir",
        "--assetsdir",
        "--assetindex",
        "--accesstoken",
        "net.minecraft.client.main",
        "knotclient",
        "launchwrapper.launch",
        "bootstraplauncher",
        "modlauncher",
        "--launchtarget",
        "moonsworth.lunar",
        "minecraft.launcher.brand",
        "fml.mcversion",
    ];
    has_any(&py_lower(&join(argv, " ")), &MARKS)
}

fn sha1_file(path: &str, limit: u64) -> String {
    let sz = match file_size(path) {
        Some(s) if s <= limit => s,
        _ => return String::new(),
    };
    let _ = sz;
    match read_file(path, -1, 0) {
        Some(d) => sha1_hex(&d),
        None => String::new(),
    }
}
const SHA1_LIMIT: u64 = 600 * 1024 * 1024;

fn zip_names_of(path: &str, limit: usize) -> StrList {
    let d = match read_file(path, -1, 0) {
        Some(d) => d,
        None => return Vec::new(),
    };
    let mut n: Vec<String> = Vec::new();
    if !zip_opens(&d, Some(&mut n)) {
        return Vec::new();
    }
    if n.len() > limit {
        n.truncate(limit);
    }
    n
}

fn zip_read_of(path: &str, name: &str, out: &mut Bytes, maxlen: u64) -> bool {
    let d = match read_file(path, -1, 0) {
        Some(d) => d,
        None => return false,
    };
    let mut z = ZipReader::new();
    if !z.open(&d) {
        return false;
    }
    let mut e = None;
    for x in z.entries() {
        if x.name == name {
            e = Some(x);
        }
    }
    match e {
        Some(e) if e.usize <= maxlen => z.read(e, out, None, None, 1u64 << 34),
        _ => false,
    }
}

fn pnorm(p: &str) -> String {
    path_norm(p)
}

fn sep_str() -> String {
    SEP.to_string()
}

fn versions_root_of(jar: &str) -> (String, String) {
    let parts = split(&path_normpath(jar), &sep_str(), -1);
    let mut k = parts.len() as i64 - 2;
    while k > 0 {
        let ku = k as usize;
        if py_lower(&parts[ku - 1]) == "versions" && ku + 1 < parts.len() {
            let mut root = join(&parts[..ku - 1], &sep_str());
            if root.is_empty() {
                root = sep_str();
            }
            return (root, parts[ku].clone());
        }
        k -= 1;
    }
    (String::new(), String::new())
}

fn version_chain(root: &str, vid: &str, depth: i32) -> Vec<JPtr> {
    if root.is_empty() || vid.is_empty() || depth > 6 {
        return Vec::new();
    }
    let j = match load_json_file(&path_join_all(&[root, "versions", vid, &format!("{vid}.json")])) {
        Some(j) if j.is_obj() => j,
        _ => return Vec::new(),
    };
    let mut out = vec![j.clone()];
    if let Some(inh) = j.get("inheritsFrom") {
        if inh.truthy() {
            out.extend(version_chain(root, &inh.py_str(), depth + 1));
        }
    }
    out
}

fn maven_path(name: &str) -> String {
    let parts = split(name, ":", -1);
    if parts.len() < 3 {
        return String::new();
    }
    let g = &parts[0];
    let a = &parts[1];
    let mut v = parts[2].clone();
    let mut ext = "jar".to_string();
    if has(&v, "@") {
        let vv = split(&v, "@", 1);
        v = vv.first().cloned().unwrap_or_default();
        ext = vv.get(1).cloned().unwrap_or_default();
    }
    let cls = if parts.len() > 3 {
        format!("-{}", parts[3])
    } else {
        String::new()
    };
    let mut segs = split(g, ".", -1);
    segs.push(a.clone());
    segs.push(v.clone());
    segs.push(format!("{a}-{v}{cls}.{ext}"));
    join(&segs, "/")
}

fn expected_library_hashes(chain: &[JPtr]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for j in chain {
        let libs = match j.get("libraries") {
            Some(l) if l.is_arr() => l,
            _ => continue,
        };
        for lib in &libs.arr {
            if !lib.is_obj() {
                continue;
            }
            let dl = lib.get("downloads");
            let art = dl.filter(|d| d.is_obj()).and_then(|d| d.get("artifact"));
            let art_obj = art.filter(|a| a.is_obj());
            let ap = art_obj.map(|a| jstr(a.get("path"))).unwrap_or_default();
            let as_ = art_obj.map(|a| jstr(a.get("sha1"))).unwrap_or_default();
            if !ap.is_empty() && !as_.is_empty() {
                out.insert(py_lower(&replace_all(&ap, "\\", "/")), lower_ascii(&as_));
            } else if !jstr(lib.get("sha1")).is_empty() && !jstr(lib.get("name")).is_empty() {
                let mp = maven_path(&jstr(lib.get("name")));
                if !mp.is_empty() {
                    out.insert(py_lower(&mp), lower_ascii(&jstr(lib.get("sha1"))));
                }
            }
            let cls = dl.filter(|d| d.is_obj()).and_then(|d| d.get("classifiers"));
            if let Some(cls) = cls.filter(|c| c.is_obj()) {
                for kv in &cls.obj {
                    if kv.1.is_obj() {
                        let cp = jstr(kv.1.get("path"));
                        let cs = jstr(kv.1.get("sha1"));
                        if !cp.is_empty() && !cs.is_empty() {
                            out.insert(py_lower(&replace_all(&cp, "\\", "/")), lower_ascii(&cs));
                        }
                    }
                }
            }
        }
    }
    out
}

fn lib_rel(path: &str) -> String {
    let low = py_lower(&replace_all(&path_normpath(path), "\\", "/"));
    match low.rfind("/libraries/") {
        Some(k) => low[k + 11..].to_string(),
        None => String::new(),
    }
}

fn is_game_jar(path: &str) -> bool {
    zip_names_of(path, 400000).iter().any(|n| {
        n == "net/minecraft/client/main/Main.class"
            || n == "net/minecraft/client/Minecraft.class"
            || n == "net/minecraft/client/MinecraftClient.class"
    })
}

fn fabric_loader_version(jars: &[String]) -> String {
    for p in jars {
        let mut b: Bytes = Vec::new();
        if !zip_read_of(p, "fabric.mod.json", &mut b, 200000) {
            continue;
        }
        let j = match json_parse(&utf8_decode(&b, 0)) {
            Some(j) if j.is_obj() => j,
            _ => continue,
        };
        let id = jstr(j.get("id"));
        if id == "fabricloader" || id == "quilt_loader" {
            let v = j.get("version");
            return format!(
                "{} {}",
                if id == "fabricloader" {
                    "Fabric Loader"
                } else {
                    "Quilt Loader"
                },
                v.map_or("None".to_string(), |v| v.py_str())
            );
        }
    }
    String::new()
}

fn scan_many(paths: &[String], stop: Option<&StopFlag>) -> BTreeMap<String, ResultP> {
    let mut out: BTreeMap<String, ResultP> = BTreeMap::new();
    let res: Mutex<Vec<Option<ResultP>>> = Mutex::new(vec![None; paths.len()]);
    let next = AtomicUsize::new(0);
    let nt = (cpu_count().clamp(1, 8)) as usize;
    std::thread::scope(|sc| {
        for _ in 0..nt.min(paths.len()) {
            let work = || loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                if i >= paths.len() || stop.is_some_and(|s| s.is_set()) {
                    break;
                }
                let r = Arc::new(scan_jar(&paths[i]));
                if let Ok(mut g) = res.lock() {
                    g[i] = Some(r);
                }
            };
            let _ = std::thread::Builder::new().stack_size(16 << 20).spawn_scoped(sc, work);
        }
    });
    let res = res.into_inner().unwrap_or_default();
    for (i, r) in res.into_iter().enumerate() {
        if let Some(r) = r {
            out.insert(paths[i].clone(), r);
        }
    }
    out
}

fn finding_labels(r: &ScanResult, lim: usize) -> StrList {
    r.findings.iter().take(lim).map(|f| f.label.clone()).collect()
}

fn ancestors_of<'a>(proc_: &'a ProcInfo, by_pid: &BTreeMap<u32, &'a ProcInfo>) -> Vec<&'a ProcInfo> {
    let mut out: Vec<&ProcInfo> = Vec::new();
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut cur = proc_;
    let mut depth = 6;
    while depth > 0 {
        let pp = match by_pid.get(&cur.ppid) {
            Some(p) => *p,
            None => break,
        };
        if seen.contains(&pp.pid) || pp.pid == cur.pid {
            break;
        }
        if let (Some(a), Some(b)) = (pp.created, cur.created) {
            if a > b {
                break;
            }
        }
        seen.insert(pp.pid);
        out.push(pp);
        cur = pp;
        depth -= 1;
    }
    out
}

fn in_list_s(s: &str, l: &[&str]) -> bool {
    l.contains(&s)
}

fn deep_scan(files: &[String], reason: &str, stop: Option<&StopFlag>) -> Vec<ResultP> {
    if files.is_empty() {
        return Vec::new();
    }
    let arc = Arc::new(StopFlag::new());
    let done = AtomicBool::new(false);
    std::thread::scope(|sc| {
        if let Some(st) = stop {
            let arc2 = arc.clone();
            let done = &done;
            sc.spawn(move || {
                while !done.load(Ordering::Relaxed) {
                    if st.is_set() {
                        arc2.set();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(30));
                }
            });
        }
        let mut ds = DiskScanner::new(Vec::new(), None, Some(arc.clone()), 0, Vec::new());
        let r = ds.scan_paths(files, reason);
        done.store(true, Ordering::Relaxed);
        r.results
    })
}

fn collect_files(root: &str, skip_dirs_lower: &[String], cap: usize) -> StrList {
    let mut out: StrList = Vec::new();
    let mut stack: Vec<String> = vec![root.to_string()];
    while !stack.is_empty() && out.len() < cap {
        let d = match stack.pop() {
            Some(d) => d,
            None => break,
        };
        let mut ents: Vec<DirEntry> = Vec::new();
        if !list_dir(&d, &mut ents) {
            continue;
        }
        for e in &ents {
            if e.is_link {
                continue;
            }
            if e.is_dir {
                if e.reparse {
                    continue;
                }
                let ln = pnorm(&e.path);
                let skip = skip_dirs_lower.contains(&ln);
                if !skip {
                    stack.push(e.path.clone());
                }
                continue;
            }
            out.push(e.path.clone());
            if out.len() >= cap {
                break;
            }
        }
    }
    out
}

#[cfg(windows)]
fn reg_java_options(root: windows::Win32::System::Registry::HKEY, path: &str, where_: &str, out: &mut StrList) {
    use windows::core::PCWSTR;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_READ, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
    };
    let wpath: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut h = HKEY::default();
    // SAFETY: wpath NUL ile biten geçerli bir tampondur; h çıkış parametresidir.
    if unsafe { RegOpenKeyExW(root, PCWSTR(wpath.as_ptr()), None, KEY_READ, &mut h) }.is_err() {
        return;
    }
    for k in ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"] {
        let wk: Vec<u16> = k.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 8192];
        let mut sz = (buf.len() * 2) as u32;
        let mut t = REG_VALUE_TYPE(0);
        // SAFETY: buf, sz bayt uzunluğuyla uyumludur.
        let r = unsafe {
            RegQueryValueExW(
                h,
                PCWSTR(wk.as_ptr()),
                None,
                Some(&mut t),
                Some(buf.as_mut_ptr() as *mut u8),
                Some(&mut sz),
            )
        };
        if r.is_ok() && (t == REG_SZ || t == REG_EXPAND_SZ) {
            let mut n = (sz as usize / 2).min(buf.len());
            while n > 0 && buf[n - 1] == 0 {
                n -= 1;
            }
            out.push(format!("{}={} ({})", k, narrow(&buf[..n]), where_));
        }
    }
    // SAFETY: h yukarıda açıldı.
    unsafe {
        let _ = RegCloseKey(h);
    }
}

fn env_java_options() -> StrList {
    let mut out: StrList = Vec::new();
    for k in ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"] {
        let v = env(k);
        if !v.is_empty() {
            out.push(format!("{k}={v}"));
        }
    }
    #[cfg(windows)]
    {
        use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
        reg_java_options(HKEY_CURRENT_USER, "Environment", "kullanıcı ortam değişkeni", &mut out);
        reg_java_options(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
            "sistem ortam değişkeni",
            &mut out,
        );
    }
    out
}

fn agents_in_options(opts: &str) -> StrList {
    let mut out: StrList = Vec::new();
    for a in split_cmdline(opts) {
        if starts(&a, "-javaagent:") {
            out.push(split1(&a[11..], "=", 0));
        }
        if starts(&a, "-agentpath:") {
            out.push(split1(&a[11..], "=", 0));
        }
    }
    out
}

fn java_home_of(exe_path: &str) -> String {
    if exe_path.is_empty() {
        return String::new();
    }
    let bin = path_dirname(exe_path);
    if py_lower(&path_basename(&bin)) != "bin" {
        return String::new();
    }
    let home = path_dirname(&bin);
    let dll = kw_jvm_dll();
    let cands = [
        path_join_all(&[&bin, "server", dll]),
        path_join_all(&[&bin, "client", dll]),
        path_join_all(&[&home, "lib", "modules"]),
        path_join_all(&[&home, "lib", "rt.jar"]),
        path_join_all(&[&home, "lib", "server", "libjvm.so"]),
    ];
    for c in cands.iter() {
        if is_file(c) {
            return home;
        }
    }
    String::new()
}

fn exe_is_java_launcher(p: &ProcInfo) -> bool {
    if p.path.is_empty() {
        return false;
    }
    let bin = path_dirname(&p.path);
    let dll = kw_jvm_dll();
    is_file(&path_join_all(&[&bin, "server", dll])) || is_file(&path_join_all(&[&bin, "client", dll]))
}

fn outer_file(file: &str) -> String {
    let a = split(file, " !/ ", -1).into_iter().next().unwrap_or_default();
    split(&a, "  (", -1).into_iter().next().unwrap_or_default()
}

fn add_deep_findings(res: &mut McProc, found: &[ResultP], ctx: &str) {
    for r in found {
        if r.rank <= 0 {
            continue;
        }
        let l = finding_labels(r, 6);
        res.findings.push(CFinding {
            rank: r.rank,
            title: format!("{}: {}", ctx, path_basename(&outer_file(&r.file))),
            detail: if l.is_empty() {
                r.verdict.clone()
            } else {
                join(&l, "; ")
            },
            path: r.file.clone(),
            result: Some(r.clone()),
        });
    }
}

#[derive(Debug, Clone, Default)]
pub struct CFinding {
    pub rank: i32,
    pub title: String,
    pub detail: String,
    pub path: String,
    pub result: Option<ResultP>,
}
#[derive(Debug, Clone, Default)]
pub struct CJar {
    pub path: String,
    pub role: String,
    pub verdict: String,
    pub rank: i32,
    pub result: Option<ResultP>,
}
#[derive(Debug, Clone, Default)]
pub struct CAncestor {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub cmd: String,
}

#[derive(Debug, Clone, Default)]
pub struct McProc {
    pub pid: u32,
    pub exe: String,
    pub started: Option<f64>,
    pub titles: StrList,
    pub cmdline: String,
    pub findings: Vec<CFinding>,
    pub notes: StrList,
    pub jars: Vec<CJar>,
    pub rank: i32,
    pub verdict: String,
    pub main_class: String,
    pub loader: String,
    pub version_arg: String,
    pub version_type: String,
    pub asset_index: String,
    pub mc_version_fml: String,
    pub forge_version: String,
    pub player: String,
    pub game_dir: String,
    pub brand: String,
    pub brand_version: String,
    pub launcher: String,
    pub game_jar: String,
    pub game_jar_sha1: String,
    pub game_jar_state: String,
    pub mc_version: String,
    pub loader_version: String,
    pub natives_dir: String,
    pub java_home: String,
    pub tweaks: StrList,
    pub version_json: StrList,
    pub bootcp: StrList,
    pub mods_dirs: StrList,
    pub agents: Vec<JavaAgent>,
    pub agentpaths: Vec<JavaAgent>,
    pub ancestors: Vec<CAncestor>,
    pub verified_libs: i32,
    pub mods: Vec<ResultP>,
    pub has_log: bool,
    pub log_file: String,
    pub log_mods: Option<usize>,
    pub log_results: Vec<LogResult>,
    pub extra_files_checked: i32,
    pub env_agents: StrList,
}

#[derive(Debug, Clone, Default)]
pub struct OtherJava {
    pub pid: u32,
    pub exe: String,
    pub cmdline: String,
    pub main: String,
    pub jars: usize,
    pub hits: Vec<ResultP>,
    pub rank: i32,
    pub verdict: String,
}

#[derive(Debug, Clone)]
pub struct Injector {
    pub pid: u32,
    pub path: String,
    pub detail: String,
    pub evidence: StrList,
    pub rank: i32,
    pub result: Option<ResultP>,
}
impl Default for Injector {
    fn default() -> Self {
        Injector {
            pid: 0,
            path: String::new(),
            detail: String::new(),
            evidence: Vec::new(),
            rank: 3,
            result: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientResult {
    pub supported: bool,
    pub time: f64,
    pub duration: f64,
    pub minecraft: Vec<McProc>,
    pub other_java: Vec<OtherJava>,
    pub injectors: Vec<Injector>,
    pub notes: StrList,
    pub errors: StrList,
    pub process_count: usize,
    pub rank: i32,
    pub verdict: String,
}
impl Default for ClientResult {
    fn default() -> Self {
        ClientResult {
            supported: true,
            time: 0.0,
            duration: 0.0,
            minecraft: Vec::new(),
            other_java: Vec::new(),
            injectors: Vec::new(),
            notes: Vec::new(),
            errors: Vec::new(),
            process_count: 0,
            rank: 0,
            verdict: "TEMIZ".to_string(),
        }
    }
}

fn analyze_minecraft(
    proc_: &ProcInfo,
    by_pid: &BTreeMap<u32, &ProcInfo>,
    titles: &BTreeMap<u32, StrList>,
    step: &dyn Fn(&str),
    stop: Option<&StopFlag>,
    covered: &mut BTreeSet<String>,
    sole_instance: bool,
) -> McProc {
    let argv0 = if !proc_.argv.is_empty() {
        proc_.argv.clone()
    } else {
        split_cmdline(&proc_.cmdline)
    };
    let argv = expand_argfiles(&argv0);
    let j = parse_java_cmdline(&argv);
    let ga = &j.game_args;
    let mut res = McProc {
        pid: proc_.pid,
        exe: if !proc_.path.is_empty() {
            proc_.path.clone()
        } else {
            proc_.name.clone()
        },
        started: proc_.created,
        ..Default::default()
    };
    if let Some(t) = titles.get(&proc_.pid) {
        res.titles = t.clone();
    }
    res.cmdline = join(&redact(&argv), " ");
    res.main_class = if !j.main.is_empty() {
        j.main.clone()
    } else if !j.jar.is_empty() {
        format!("-jar {}", j.jar)
    } else {
        "?".to_string()
    };
    res.loader = main_class_name(&j.main);
    let lt = game_arg(ga, "--launchTarget");
    if !lt.is_empty() {
        res.loader = format!("{} / hedef: {}", res.loader, lt);
    }
    res.tweaks = game_args_multi(ga, "--tweakClass");
    res.version_arg = game_arg(ga, "--version");
    res.version_type = game_arg(ga, "--versionType");
    res.asset_index = game_arg(ga, "--assetIndex");
    res.mc_version_fml = game_arg(ga, "--fml.mcVersion");
    res.forge_version = game_arg(ga, "--fml.forgeVersion");
    if res.forge_version.is_empty() {
        res.forge_version = game_arg(ga, "--fml.neoForgeVersion");
    }
    res.player = game_arg(ga, "--username");
    let mut gdir = game_arg(ga, "--gameDir");
    if gdir.is_empty() {
        gdir = game_arg(ga, "--workDir");
    }
    res.game_dir = gdir.clone();
    res.brand = j.prop("minecraft.launcher.brand");
    res.brand_version = j.prop("minecraft.launcher.version");
    let anc = ancestors_of(proc_, by_pid);
    for a in &anc {
        res.ancestors.push(CAncestor {
            pid: a.pid,
            name: a.name.clone(),
            path: a.path.clone(),
            cmd: uslice(&join(&redact(&split_cmdline(&a.cmdline)), " "), 400),
        });
    }
    static JAVA_RX: OnceLock<Rx> = OnceLock::new();
    let java_rx = JAVA_RX.get_or_init(|| Rx::new(r"(^|[\\/])javaw?(\.exe)?$", Rx::I));
    let mut lname = String::new();
    for a in &anc {
        let pn = if !a.path.is_empty() { &a.path } else { &a.name };
        lname = launcher_name(pn);
        if lname.is_empty() && java_rx.search(pn.as_bytes(), 0).is_some() {
            let pj = parse_java_cmdline(&split_cmdline(&a.cmdline));
            lname = launcher_name(&pj.jar);
            if lname.is_empty() {
                lname = launcher_name(&pj.main);
            }
        }
        if !lname.is_empty() {
            break;
        }
    }
    if lname.is_empty() {
        lname = launcher_name(&res.brand);
        if lname.is_empty() {
            lname = launcher_name(&join(&argv[..argv.len().min(3)], " "));
        }
    }
    res.launcher = lname;
    if !j.main.is_empty() && main_class_name(&j.main).is_empty() {
        res.notes.push(format!(
            "Standart olmayan giriş sınıfı: {} (çalıştırılan jar'lar aşağıda kod olarak incelendi)",
            j.main
        ));
    }

    let mut all_paths: StrList = Vec::new();
    for v in [&j.cp, &j.module_path, &j.bootcp, &j.extra_paths] {
        for p in v.iter() {
            all_paths.push(p.clone());
        }
    }
    if !j.jar.is_empty() {
        all_paths.push(j.jar.clone());
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut jars: StrList = Vec::new();
    let mut cp_dirs: StrList = Vec::new();
    for p in all_paths {
        let p = strip(&pystrip(&p), "\"");
        if p.is_empty() {
            continue;
        }
        if ends(&p, "*") && is_dir(&path_dirname(&p)) {
            let dn = path_dirname(&p);
            for n in listdir_names(&dn) {
                let fp = path_join(&dn, &n);
                if ends(&py_lower(&n), ".jar") && is_file(&fp) && seen.insert(pnorm(&fp)) {
                    jars.push(fp);
                }
            }
            continue;
        }
        if is_dir(&p) {
            if seen.insert(pnorm(&p)) {
                cp_dirs.push(p);
            }
            continue;
        }
        if !seen.insert(pnorm(&p)) {
            continue;
        }
        jars.push(p);
    }
    let agents: StrList = j.agents.iter().map(|a| a.path.clone()).collect();
    let mut game_jar = String::new();
    for p in &jars {
        if is_file(p) && is_game_jar(p) {
            game_jar = p.clone();
            break;
        }
    }
    let rv = if game_jar.is_empty() {
        (String::new(), String::new())
    } else {
        versions_root_of(&game_jar)
    };
    let mut root = rv.0;
    let vid = rv.1;
    let mut chain: Vec<JPtr> = Vec::new();
    if !game_jar.is_empty() && !root.is_empty() {
        chain = version_chain(&root, &vid, 0);
    }
    if !res.version_arg.is_empty() && !root.is_empty() {
        let c2 = version_chain(&root, &res.version_arg, 0);
        if !c2.is_empty() {
            chain = c2;
        }
    }
    if !res.version_arg.is_empty() && chain.is_empty() {
        for p in &jars {
            let r2 = versions_root_of(p);
            if !r2.0.is_empty() {
                chain = version_chain(&r2.0, &res.version_arg, 0);
                if root.is_empty() {
                    root = r2.0.clone();
                }
                if !chain.is_empty() {
                    break;
                }
            }
        }
    }
    if chain.is_empty() && !gdir.is_empty() {
        chain = version_chain(&gdir, &res.version_arg, 0);
    }
    res.game_jar = game_jar.clone();
    for c in &chain {
        res.version_json
            .push(c.get("id").map_or("?".to_string(), |v| v.py_str()));
    }
    let mut mc_ver = String::new();
    for c in &chain {
        let dl = c.get("downloads");
        if let Some(dl) = dl {
            if dl.is_obj() && jtruthy(dl.get("client")) {
                mc_ver = jstr(c.get("id"));
            }
        }
    }
    res.mc_version = if !mc_ver.is_empty() {
        mc_ver
    } else if !res.mc_version_fml.is_empty() {
        res.mc_version_fml.clone()
    } else if let Some(last) = chain.last() {
        jstr(last.get("id"))
    } else {
        String::new()
    };
    let existing: StrList = jars.iter().filter(|p| is_file(p)).cloned().collect();
    res.loader_version = fabric_loader_version(&existing);
    if res.loader_version.is_empty() && !res.forge_version.is_empty() {
        res.loader_version = format!("Forge/NeoForge {}", res.forge_version);
    }

    let mut ref_ = String::new();
    if !game_jar.is_empty() && !root.is_empty() && !vid.is_empty() {
        let own = version_chain(&root, &vid, 0);
        if let Some(o0) = own.first() {
            let cl = o0.get("downloads").filter(|d| d.is_obj()).and_then(|d| d.get("client"));
            let s1 = cl
                .filter(|c| c.is_obj())
                .map(|c| jstr(c.get("sha1")))
                .unwrap_or_default();
            if !s1.is_empty() && py_lower(&path_basename(&game_jar)) == py_lower(&format!("{vid}.jar")) {
                ref_ = lower_ascii(&s1);
            }
        }
    }
    let mut official_game = false;
    if !game_jar.is_empty() {
        let h = sha1_file(&game_jar, SHA1_LIMIT);
        res.game_jar_sha1 = h.clone();
        if !ref_.is_empty() && !h.is_empty() {
            if h == ref_ {
                res.game_jar_state = "Resmi Mojang dosyasıyla BİREBİR aynı (SHA-1 doğrulandı)".to_string();
                official_game = true;
            } else {
                res.game_jar_state = format!("RESMİ DOSYADAN FARKLI (SHA-1 {h}, beklenen {ref_})");
                res.findings.push(CFinding {
                    rank: 1,
                    title: "Değiştirilmiş oyun dosyası".to_string(),
                    detail: "Çalışan sürümün oyun jar'i, sürüm JSON'undaki resmi Mojang SHA-1 değeriyle eşleşmiyor: \
                             oyunun kendisi değiştirilmiş (hileli sürüm olabilir). Jar'in kodu ayrıca incelendi."
                        .to_string(),
                    path: game_jar.clone(),
                    result: None,
                });
            }
        } else {
            res.game_jar_state = "Resmi SHA-1 bilgisi bulunamadı (karşılaştırılamadı)".to_string();
        }
    }

    let expected = expected_library_hashes(&chain);
    let mut to_scan: StrList = Vec::new();
    let mut verified = 0;
    for p in &jars {
        if !is_file(p) {
            res.notes
                .push(format!("Komut satırındaki dosya bulunamadı (silinmiş / taşınmış): {p}"));
            continue;
        }
        covered.insert(pnorm(p));
        if official_game && *p == game_jar {
            verified += 1;
            continue;
        }
        let rel = lib_rel(p);
        if !rel.is_empty() {
            if let Some(exp) = expected.get(&rel) {
                let h = sha1_file(p, SHA1_LIMIT);
                if !h.is_empty() && h == *exp {
                    verified += 1;
                    continue;
                }
            }
        }
        to_scan.push(p.clone());
    }
    let mut ts: BTreeSet<String> = to_scan.iter().map(|x| pnorm(x)).collect();
    for v in [&agents, &j.extra_paths] {
        for a in v.iter() {
            if is_file(a) && !ts.contains(&pnorm(a)) {
                to_scan.push(a.clone());
                ts.insert(pnorm(a));
                covered.insert(pnorm(a));
            }
        }
    }
    res.verified_libs = verified;
    res.agents = j.agents.clone();
    res.agentpaths = j.agentpaths.clone();
    res.bootcp = j.bootcp.clone();
    step(&format!(
        "Çalışan istemcinin {} jar'inin kodu okunuyor...",
        to_scan.len()
    ));
    let scanned = scan_many(&to_scan, stop);
    let agent_n: BTreeSet<String> = agents.iter().map(|a| pnorm(a)).collect();
    let boot_n: BTreeSet<String> = j.bootcp.iter().map(|b| pnorm(&strip(b, "\""))).collect();
    for p in &to_scan {
        let r = scanned.get(p).cloned();
        let role = if agent_n.contains(&pnorm(p)) {
            "Java ajanı (-javaagent)"
        } else if boot_n.contains(&pnorm(p)) {
            "bootclasspath'e eklenmiş"
        } else if *p == game_jar {
            "oyun jar'i"
        } else {
            "classpath"
        };
        res.jars.push(CJar {
            path: p.clone(),
            role: role.to_string(),
            verdict: r.as_ref().map_or("?".to_string(), |r| r.verdict.clone()),
            rank: r.as_ref().map_or(0, |r| r.rank),
            result: r.clone(),
        });
        if let Some(r) = &r {
            if r.rank > 0 {
                let l = finding_labels(r, 6);
                res.findings.push(CFinding {
                    rank: r.rank,
                    title: format!("{}: {}", role, path_basename(p)),
                    detail: if l.is_empty() {
                        r.verdict.clone()
                    } else {
                        join(&l, "; ")
                    },
                    path: p.clone(),
                    result: Some(r.clone()),
                });
            }
        }
    }

    for d in &cp_dirs {
        step(&format!("Classpath / addMods klasörü inceleniyor: {d}"));
        let files = collect_files(d, &[], 50000);
        for f in &files {
            covered.insert(pnorm(f));
        }
        res.extra_files_checked += files.len() as i32;
        let found = deep_scan(
            &files,
            &format!("Çalışan oyunun classpath / addMods klasörü: {d}"),
            stop,
        );
        add_deep_findings(&mut res, &found, "Classpath / addMods klasörü");
        for r in scan_directory(d, None, 0) {
            if r.rank > 0 {
                let l = finding_labels(&r, 6);
                let f = CFinding {
                    rank: r.rank,
                    title: format!("Classpath / addMods klasöründeki mod: {}", r.name),
                    detail: if l.is_empty() {
                        r.verdict.clone()
                    } else {
                        join(&l, "; ")
                    },
                    path: r.file.clone(),
                    result: Some(Arc::new(r)),
                };
                res.findings.push(f);
            }
        }
    }

    let mut natives = j.prop("java.library.path");
    if natives.is_empty() {
        natives = j.prop("org.lwjgl.librarypath");
    }
    let mut dlls: StrList = Vec::new();
    for a in &j.agentpaths {
        dlls.push(a.path.clone());
    }
    for d in split(&natives, PATHSEP, -1) {
        if d.is_empty() || !is_dir(&d) {
            continue;
        }
        for fp in collect_files(&d, &[], 5000) {
            dlls.push(fp);
        }
    }
    res.natives_dir = natives;
    let mut dll_ok: StrList = Vec::new();
    for dp in &dlls {
        let data = match read_file(dp, 64 * 1024 * 1024, 0) {
            Some(d) => d,
            None => continue,
        };
        dll_ok.push(dp.clone());
        covered.insert(pnorm(dp));
        let mut ex = String::new();
        let mut ev: StrList = Vec::new();
        if pe_injector_check(&data, &mut ex, &mut ev) {
            res.findings.push(CFinding {
                rank: 3,
                title: format!("Oyuna yüklenen yerel kod: {}", path_basename(dp)),
                detail: ex,
                path: dp.clone(),
                result: None,
            });
        }
    }
    res.extra_files_checked += dll_ok.len() as i32;
    {
        let found = deep_scan(&dll_ok, "Oyunun yerel kod (natives / -agentpath) dosyası", stop);
        let nonpe: Vec<ResultP> = found.into_iter().filter(|r| r.kind != "Yerel program (PE)").collect();
        add_deep_findings(&mut res, &nonpe, "Natives / yerel ajan");
    }
    for a in &j.agentpaths {
        res.notes.push(format!(
            "JVM'e başlangıçta yerel ajan yüklendi (-agentpath): {}",
            a.path
        ));
    }
    for f in &j.jvm_flags {
        let lf = py_lower(f);
        if lf == "-noverify" || lf == "-xverify:none" {
            res.notes.push(format!(
                "Bytecode doğrulaması kapatılmış ({f}): değiştirilmiş/enjekte edilmiş sınıf yüklemeyi kolaylaştırır (tek başına kanıt değil)."
            ));
        }
    }

    if !gdir.is_empty() {
        let md = path_join(&gdir, "mods");
        if is_dir(&md) {
            res.mods_dirs.push(md);
        }
    }
    for md in res.mods_dirs.clone() {
        step(&format!("Oyun klasöründeki mods taranıyor: {md}"));
        for r in scan_directory(&md, None, 0) {
            let rp = Arc::new(r);
            covered.insert(pnorm(&rp.file));
            res.mods.push(rp.clone());
            if rp.rank > 0 {
                let l = finding_labels(&rp, 6);
                res.findings.push(CFinding {
                    rank: rp.rank,
                    title: format!("Yüklü mod: {}", rp.name),
                    detail: join(&l, "; "),
                    path: rp.file.clone(),
                    result: Some(rp.clone()),
                });
            }
        }
    }

    if !gdir.is_empty() && is_dir(&path_join(&gdir, "logs")) {
        let latest = path_join_all(&[&gdir, "logs", "latest.log"]);
        let mut fresh = false;
        let mt = file_mtime(&latest);
        if is_file(&latest) {
            if let Some(mt) = mt {
                fresh = proc_.created.is_none_or(|c| mt >= c - 120.0);
            }
        }
        if fresh {
            let dirs: StrList = vec![path_join(&gdir, "logs")];
            let md0 = res.mods_dirs.first().cloned().unwrap_or_default();
            let lr = scan_logs(2, &md0, Some(&dirs), None, 0.0);
            apply_log_scan(&mut res, &lr, &latest, "Bu oturumun logunda: ");
        }
    }

    if !res.has_log && sole_instance && proc_.created.is_some() {
        let created = proc_.created.unwrap_or(0.0);
        let own = if gdir.is_empty() {
            String::new()
        } else {
            path_norm(&path_join(&gdir, "logs"))
        };
        let mut fresh: Vec<(String, String)> = Vec::new(); // (log dosyası, klasörü)
        for d in launcher_log_dirs() {
            if !own.is_empty() && path_norm(&d) == own {
                continue;
            }
            let mut ents: Vec<DirEntry> = Vec::new();
            if !list_dir(&d, &mut ents) {
                continue;
            }
            for e in &ents {
                if !e.is_file || !ends(&py_lower(&e.name), ".log") {
                    continue;
                }
                if e.mtime != 0.0 && e.mtime >= created - 120.0 {
                    fresh.push((e.path.clone(), d.clone()));
                }
            }
        }
        if fresh.len() == 1 {
            let latest = fresh[0].0.clone();
            let dirs: StrList = vec![fresh[0].1.clone()];
            let md0 = res.mods_dirs.first().cloned().unwrap_or_default();
            let lr = scan_logs(2, &md0, Some(&dirs), None, 0.0);
            apply_log_scan(&mut res, &lr, &latest, "Bu oturumun logunda (başlatıcı log klasörü): ");
        }
    }

    if !gdir.is_empty() && is_dir(&gdir) {
        step(&format!(
            "Oyun klasörü (tüm alt klasörler) kod motoruyla taranıyor: {gdir}"
        ));
        let mut skip: StrList = Vec::new();
        for s in [
            "saves",
            "screenshots",
            "logs",
            "crash-reports",
            "assets",
            "versions",
            "libraries",
            "runtime",
            "mods",
            "backups",
            "replay_recordings",
            ".cache",
        ] {
            skip.push(pnorm(&path_join(&gdir, s)));
        }
        let mut files: StrList = Vec::new();
        for f in collect_files(&gdir, &skip, 100000) {
            if !covered.contains(&pnorm(&f)) {
                files.push(f);
            }
        }
        for f in &files {
            covered.insert(pnorm(f));
        }
        res.extra_files_checked += files.len() as i32;
        let found = deep_scan(&files, &format!("Çalışan oyunun oyun klasöründe: {gdir}"), stop);
        add_deep_findings(&mut res, &found, "Oyun klasöründe");
    }

    {
        const SKIP_KEYS: [&str; 24] = [
            "--gameDir",
            "--workDir",
            "--assetsDir",
            "--assetIndex",
            "--version",
            "--username",
            "--uuid",
            "--accessToken",
            "--userType",
            "--versionType",
            "--launchTarget",
            "--fml.mcVersion",
            "--fml.forgeVersion",
            "--fml.neoForgeVersion",
            "--fml.mcpVersion",
            "--fml.forgeGroup",
            "--width",
            "--height",
            "--clientId",
            "--xuid",
            "--quickPlayPath",
            "--quickPlaySingleplayer",
            "--quickPlayMultiplayer",
            "--server",
        ];
        const SKIP_KEYS2: [&str; 1] = ["--port"];
        const SKIP_PROPS: [&str; 23] = [
            "java.library.path",
            "org.lwjgl.librarypath",
            "java.io.tmpdir",
            "user.home",
            "user.dir",
            "java.home",
            "jna.tmpdir",
            "org.lwjgl.system.SharedLibraryExtractPath",
            "io.netty.native.workdir",
            "legacyClassPath",
            "fabric.gameJarPath",
            "fabric.addMods",
            "minecraft.launcher.brand",
            "minecraft.launcher.version",
            "log4j.configurationFile",
            "log4j2.formatMsgNoLookups",
            "os.name",
            "os.version",
            "file.encoding",
            "stdout.encoding",
            "stderr.encoding",
            "sun.stdout.encoding",
            "sun.stderr.encoding",
        ];
        let mut cands: StrList = Vec::new();
        for i in 0..ga.len().saturating_sub(1) {
            if starts(&ga[i], "--") && !in_list_s(&ga[i], &SKIP_KEYS) && !in_list_s(&ga[i], &SKIP_KEYS2) {
                cands.push(ga[i + 1].clone());
            }
        }
        for kv in &j.props {
            if !in_list_s(&kv.0, &SKIP_PROPS) {
                for x in cp_paths(&kv.1) {
                    cands.push(x);
                }
            }
        }
        let mut files: StrList = Vec::new();
        for c in cands {
            let c = strip(&pystrip(&c), "\"");
            if c.is_empty() || !path_isabs(&c) {
                continue;
            }
            if is_file(&c) {
                if !covered.contains(&pnorm(&c)) {
                    files.push(c);
                }
            } else if is_dir(&c) && pnorm(&c) != pnorm(&gdir) {
                for f in collect_files(&c, &[], 20000) {
                    if !covered.contains(&pnorm(&f)) {
                        files.push(f);
                    }
                }
            }
        }
        for f in &files {
            covered.insert(pnorm(f));
        }
        res.extra_files_checked += files.len() as i32;
        let found = deep_scan(&files, "Çalışan oyunun komut satırında gösterilen yol", stop);
        add_deep_findings(&mut res, &found, "Komut satırı yolu");
    }

    let jh = java_home_of(&proc_.path);
    res.java_home = jh.clone();
    if !jh.is_empty() {
        step(&format!("Oyunu çalıştıran Java (JRE) inceleniyor: {jh}"));
        let mut files: StrList = Vec::new();
        for f in collect_files(&jh, &[], 20000) {
            if !covered.contains(&pnorm(&f)) {
                files.push(f);
            }
        }
        for f in &files {
            covered.insert(pnorm(f));
        }
        res.extra_files_checked += files.len() as i32;
        let found = deep_scan(&files, "Oyunu çalıştıran Java (JRE) klasöründe", stop);
        add_deep_findings(&mut res, &found, "Java (JRE) klasöründe");
    }

    #[cfg(windows)]
    if let Some(created) = proc_.created {
        let mut files: StrList = Vec::new();
        for pf in parse_prefetch_dir(&prefetch_dir()) {
            if !is_java_prefetch(&pf) {
                continue;
            }
            let this_session = pf.run_times.iter().any(|&t| t >= created - 120.0);
            if !this_session {
                continue;
            }
            for raw in &pf.filenames {
                let up = py_upper(raw);
                if has(&up, "\\WINDOWS\\") {
                    continue;
                }
                let local = resolve_nt_path(raw);
                if local.is_empty() || !is_file(&local) || covered.contains(&pnorm(&local)) {
                    continue;
                }
                files.push(local.clone());
                covered.insert(pnorm(&local));
            }
        }
        res.extra_files_checked += files.len() as i32;
        let found = deep_scan(&files, "Prefetch: bu oturumda Java (javaw) tarafından yüklendi", stop);
        add_deep_findings(&mut res, &found, "Bu oturumda Java'nin yüklediği dosya (Prefetch)");
    }

    {
        let mut files: StrList = Vec::new();
        for o in env_java_options() {
            res.env_agents.push(o.clone());
            for a in agents_in_options(&split1(&o, "=", 1)) {
                let p = strip(&a, "\"");
                if is_file(&p) && !covered.contains(&pnorm(&p)) {
                    files.push(p.clone());
                    covered.insert(pnorm(&p));
                }
            }
        }
        if !res.env_agents.is_empty() {
            res.notes.push(format!(
                "Java'yi etkileyen ortam değişkeni bulundu (komut satırında GÖRÜNMEDEN ajan ekleyebilir): {}",
                join(&res.env_agents, " | ")
            ));
        }
        if !files.is_empty() {
            let sc = scan_many(&files, stop);
            for (k, v) in &sc {
                if v.rank > 0 {
                    let l = finding_labels(v, 6);
                    res.findings.push(CFinding {
                        rank: v.rank,
                        title: format!("Ortam değişkeniyle eklenen Java ajanı: {}", path_basename(k)),
                        detail: if l.is_empty() {
                            v.verdict.clone()
                        } else {
                            join(&l, "; ")
                        },
                        path: k.clone(),
                        result: Some(v.clone()),
                    });
                }
            }
            let found = deep_scan(
                &files,
                "Ortam değişkeniyle (JAVA_TOOL_OPTIONS) eklenen Java ajanı",
                stop,
            );
            add_deep_findings(&mut res, &found, "Ortam değişkeni ajanı");
            res.extra_files_checked += files.len() as i32;
        }
    }

    {
        let mut uniq: Vec<CFinding> = Vec::new();
        let mut by: BTreeMap<String, usize> = BTreeMap::new();
        for f in &res.findings {
            if f.path.is_empty() || f.result.is_none() {
                uniq.push(f.clone());
                continue;
            }
            let k = pnorm(&f.path);
            match by.get(&k) {
                None => {
                    by.insert(k, uniq.len());
                    uniq.push(f.clone());
                }
                Some(&ix) => {
                    if f.rank > uniq[ix].rank {
                        uniq[ix] = f.clone();
                    }
                }
            }
        }
        res.findings = uniq;
    }
    res.rank = 0;
    for f in &res.findings {
        res.rank = res.rank.max(f.rank);
    }
    res.verdict = rank_verdict(res.rank);
    res
}

fn apply_log_scan(res: &mut McProc, lr: &LogScan, latest: &str, title_prefix: &str) {
    res.has_log = true;
    res.log_file = latest.to_string();
    for r in &lr.results {
        let mut mine = pnorm(&r.file) == pnorm(latest);
        for x in &r.same_session {
            if pnorm(x) == pnorm(latest) {
                mine = true;
            }
        }
        if mine {
            res.log_results.push(r.clone());
        }
    }
    for s in &lr.files {
        if pnorm(&s.file) == pnorm(latest) {
            res.log_mods = Some(s.mods);
        }
    }
    let lrs = res.log_results.clone();
    for r in &lrs {
        let ids: StrList = r.hits.iter().map(|h| h.r#mod.id.clone()).collect();
        res.findings.push(CFinding {
            rank: r.rank,
            title: uslice(&format!("{}{}", title_prefix, join(&ids, ", ")), 120),
            detail: r.verdict.clone(),
            path: latest.to_string(),
            result: None,
        });
    }
}

fn analyze_other_java(proc_: &ProcInfo, stop: Option<&StopFlag>) -> OtherJava {
    let argv = if !proc_.argv.is_empty() {
        proc_.argv.clone()
    } else {
        split_cmdline(&proc_.cmdline)
    };
    let j = parse_java_cmdline(&argv);
    let mut paths: StrList = Vec::new();
    for v in [&j.cp, &j.module_path] {
        for p in v.iter() {
            paths.push(p.clone());
        }
    }
    if !j.jar.is_empty() {
        paths.push(j.jar.clone());
    }
    for a in &j.agents {
        paths.push(a.path.clone());
    }
    let mut inst: StrList = Vec::new();
    for k in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "SystemRoot"] {
        let v = env(k);
        if !v.is_empty() {
            inst.push(format!("{}{}", pnorm(&v), SEP));
        }
    }
    let mut keep: StrList = Vec::new();
    for p0 in &paths {
        let p = strip(p0, "\"");
        if p.is_empty() || !is_file(&p) {
            continue;
        }
        let np = pnorm(&p);
        let in_inst = inst.iter().any(|x| starts(&np, x));
        if in_inst {
            continue;
        }
        keep.push(p);
        if keep.len() >= 40 {
            break;
        }
    }
    let scanned = scan_many(&keep, stop);
    let mut o = OtherJava {
        pid: proc_.pid,
        exe: if !proc_.path.is_empty() {
            proc_.path.clone()
        } else {
            proc_.name.clone()
        },
        cmdline: uslice(&join(&redact(&argv), " "), 600),
        main: if !j.main.is_empty() {
            j.main.clone()
        } else if !j.jar.is_empty() {
            format!("-jar {}", j.jar)
        } else {
            String::new()
        },
        jars: keep.len(),
        ..Default::default()
    };
    for p in &keep {
        if let Some(r) = scanned.get(p) {
            if r.rank > 0 {
                o.hits.push(r.clone());
                o.rank = o.rank.max(r.rank);
            }
        }
    }
    o.verdict = rank_verdict(o.rank);
    o
}

pub fn scan_active_clients(
    progress: Option<StrProgress>,
    procs_override: Option<&[ProcInfo]>,
    stop: Option<&StopFlag>,
) -> ClientResult {
    let mut res = ClientResult::default();
    let t0 = now_epoch();
    res.time = t0;
    let step = |m: &str| {
        if let Some(p) = progress {
            p(m);
        }
    };
    step("Çalışan süreçler okunuyor...");
    let mut plist: Vec<ProcInfo> = match procs_override {
        Some(o) => o.to_vec(),
        None => list_processes(),
    };
    res.process_count = plist.len();
    let me = std::process::id();
    for p in plist.iter_mut() {
        if p.argv.is_empty() {
            p.argv = split_cmdline(&p.cmdline);
        }
    }
    let mut by_pid: BTreeMap<u32, &ProcInfo> = BTreeMap::new();
    for p in &plist {
        by_pid.insert(p.pid, p);
    }
    let titles = window_titles();
    static JRX: OnceLock<Rx> = OnceLock::new();
    let jrx = JRX.get_or_init(|| Rx::new(r"(^|[\\/])(java|javaw)(\.exe)?$", Rx::I));
    let mut javas: Vec<usize> = Vec::new();
    let mut mc: Vec<usize> = Vec::new();
    for (ix, p) in plist.iter().enumerate() {
        if p.pid == me || p.argv.is_empty() {
            continue;
        }
        if jrx.search(strip(&p.argv[0], "\"").as_bytes(), 0).is_some() || exe_is_java_launcher(p) {
            javas.push(ix);
        }
    }
    for &ix in &javas {
        if is_minecraft_cmdline(&plist[ix].argv) {
            mc.push(ix);
        }
    }
    for (ix, p) in plist.iter().enumerate() {
        if p.pid == me || p.argv.is_empty() || mc.contains(&ix) {
            continue;
        }
        if !is_minecraft_cmdline(&p.argv) {
            continue;
        }
        let mut ok = false;
        for i in 1..p.argv.len().min(6) {
            if p.argv[i] == "-cp" || p.argv[i] == "-classpath" || starts(&p.argv[i], "-Djava") {
                ok = true;
            }
        }
        if ok {
            mc.push(ix);
        }
    }
    {
        let pids: BTreeSet<u32> = mc.iter().map(|&i| plist[i].pid).collect();
        let mut keep: Vec<usize> = Vec::new();
        for &i in &mc {
            let p = &plist[i];
            let wrapper = mc
                .iter()
                .any(|&qi| plist[qi].ppid == p.pid && pids.contains(&plist[qi].pid));
            if !wrapper {
                keep.push(i);
            }
        }
        mc = keep;
    }
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for &i in &mc {
        if stop.is_some_and(|s| s.is_set()) {
            break;
        }
        let p = &plist[i];
        step(&format!("Minecraft süreci inceleniyor (PID {})...", p.pid));
        res.minecraft.push(analyze_minecraft(
            p,
            &by_pid,
            &titles,
            &step,
            stop,
            &mut covered,
            mc.len() == 1,
        ));
    }
    for &i in &javas {
        if stop.is_some_and(|s| s.is_set()) {
            break;
        }
        if mc.contains(&i) {
            continue;
        }
        let p = &plist[i];
        step(&format!("Diğer Java süreci inceleniyor (PID {})...", p.pid));
        res.other_java.push(analyze_other_java(p, stop));
    }
    step("Çalışan programlar enjeksiyon izi için inceleniyor...");
    {
        let mut sysroot = env("SystemRoot");
        if sysroot.is_empty() {
            sysroot = env("windir");
        }
        let sysn = if sysroot.is_empty() {
            String::new()
        } else {
            format!("{}{}", pnorm(&sysroot), SEP)
        };
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut exes: StrList = Vec::new();
        let mut pid_of: BTreeMap<String, u32> = BTreeMap::new();
        for p in &plist {
            if p.pid == me || p.path.is_empty() {
                continue;
            }
            let np = pnorm(&p.path);
            if seen.contains(&np) || !is_file(&p.path) {
                continue;
            }
            seen.insert(np.clone());
            if !sysn.is_empty() && starts(&np, &sysn) {
                continue;
            }
            exes.push(p.path.clone());
            pid_of.insert(np, p.pid);
        }
        let mut flagged: BTreeSet<String> = BTreeSet::new();
        for path in &exes {
            if stop.is_some_and(|s| s.is_set()) {
                break;
            }
            match file_size(path) {
                Some(sz) if sz <= 64 * 1024 * 1024 => {}
                _ => continue,
            }
            let data = match read_file(path, -1, 0) {
                Some(d) => d,
                None => continue,
            };
            let mut ex = String::new();
            let mut ev: StrList = Vec::new();
            if pe_injector_check(&data, &mut ex, &mut ev) {
                res.injectors.push(Injector {
                    pid: pid_of.get(&pnorm(path)).copied().unwrap_or(0),
                    path: path.clone(),
                    detail: ex,
                    evidence: ev,
                    ..Default::default()
                });
                flagged.insert(pnorm(path));
            }
        }
        for r in deep_scan(&exes, "Çalışan program", stop) {
            let outer = outer_file(&r.file);
            if r.rank <= 0 || flagged.contains(&pnorm(&outer)) {
                continue;
            }
            let l = finding_labels(&r, 4);
            res.injectors.push(Injector {
                pid: pid_of.get(&pnorm(&outer)).copied().unwrap_or(0),
                path: r.file.clone(),
                rank: r.rank,
                detail: format!("Çalışan programın dosyasında gömülü kod bulundu: {}", join(&l, "; ")),
                result: Some(r.clone()),
                ..Default::default()
            });
        }
    }
    if mc.is_empty() {
        res.notes
            .push("Şu an çalışan bir Minecraft istemcisi bulunamadı (tarama anında oyun açık değildi).".to_string());
    }
    res.rank = 0;
    for m in &res.minecraft {
        res.rank = res.rank.max(m.rank);
    }
    for o in &res.other_java {
        res.rank = res.rank.max(o.rank);
    }
    for i in &res.injectors {
        res.rank = res.rank.max(i.rank);
    }
    res.verdict = rank_verdict(res.rank);
    res.duration = now_epoch() - t0;
    res
}

pub fn client_lines(m: &McProc, indent: &str) -> StrList {
    let i = indent;
    let dash = |s: &String| if s.is_empty() { "-".to_string() } else { s.clone() };
    let mut l: StrList = Vec::new();
    l.push(format!(
        "{i}[{}] Minecraft süreci PID {}",
        goster_buyuk(&m.verdict),
        m.pid
    ));
    l.push(format!("{i}  Çalıştırılabilir : {}", m.exe));
    l.push(format!("{i}  Başlangıç        : {}", fmt_dt(m.started)));
    if !m.titles.is_empty() {
        l.push(format!(
            "{i}  Pencere başlığı  : {}",
            join(&m.titles[..m.titles.len().min(3)], " | ")
        ));
    }
    l.push(format!("{i}  Oyuncu           : {}", dash(&m.player)));
    l.push(format!("{i}  Minecraft sürümü : {}", dash(&m.mc_version)));
    l.push(format!(
        "{i}  Profil (--version): {}{}",
        dash(&m.version_arg),
        if m.version_type.is_empty() {
            String::new()
        } else {
            format!("  (tür: {})", m.version_type)
        }
    ));
    if !m.version_json.is_empty() {
        l.push(format!("{i}  Sürüm zinciri    : {}", join(&m.version_json, " -> ")));
    }
    l.push(format!(
        "{i}  Yükleyici        : {}{}",
        if m.loader.is_empty() { "bilinmiyor" } else { &m.loader },
        if m.loader_version.is_empty() {
            String::new()
        } else {
            format!("  [{}]", m.loader_version)
        }
    ));
    if !m.tweaks.is_empty() {
        l.push(format!("{i}  tweakClass       : {}", join(&m.tweaks, ", ")));
    }
    l.push(format!("{i}  Giriş sınıfı     : {}", m.main_class));
    l.push(format!(
        "{i}  Başlatıcı        : {}{}",
        if m.launcher.is_empty() {
            "belirlenemedi"
        } else {
            &m.launcher
        },
        if m.brand.is_empty() {
            String::new()
        } else {
            format!("  (launcher.brand={} {})", m.brand, m.brand_version)
        }
    ));
    for a in m.ancestors.iter().take(4) {
        l.push(format!(
            "{i}     üst süreç    : PID {}  {}",
            a.pid,
            if a.path.is_empty() { &a.name } else { &a.path }
        ));
    }
    l.push(format!("{i}  Oyun klasörü     : {}", dash(&m.game_dir)));
    if !m.game_jar.is_empty() {
        l.push(format!("{i}  Oyun jar'i       : {}", m.game_jar));
        l.push(format!("{i}     durum        : {}", dash(&m.game_jar_state)));
    }
    l.push(format!(
        "{i}  Kod incelemesi   : {} jar okundu, {} kütüphane resmi SHA-1 ile doğrulandı",
        m.jars.len(),
        m.verified_libs
    ));
    if m.extra_files_checked != 0 {
        l.push(format!(
            "{i}  Ek kod taraması  : {} dosya (oyun klasörünün tamamı, Java/JRE klasörü, natives, komut satırı yolları, bu oturumun Prefetch kaydı, ortam değişkeni ajanları)",
            m.extra_files_checked
        ));
    }
    if !m.java_home.is_empty() {
        l.push(format!("{i}  Java (JRE)       : {}", m.java_home));
    }
    for a in &m.agents {
        l.push(format!(
            "{i}  Java ajanı       : {} {}",
            a.path,
            if a.options.is_empty() {
                String::new()
            } else {
                format!("={}", a.options)
            }
        ));
    }
    for a in &m.agentpaths {
        l.push(format!("{i}  Yerel ajan       : {}", a.path));
    }
    for b in &m.bootcp {
        l.push(format!("{i}  bootclasspath    : {b}"));
    }
    if !m.natives_dir.is_empty() {
        l.push(format!("{i}  Natives klasörü  : {}", m.natives_dir));
    }
    for md in &m.mods_dirs {
        l.push(format!(
            "{i}  Mods klasörü     : {md}  ({} dosya kod olarak okundu)",
            m.mods.len()
        ));
    }
    if m.has_log {
        l.push(format!(
            "{i}  Oturum logu      : {}  ({} mod yüklü)",
            m.log_file,
            m.log_mods.map_or("-".to_string(), |v| itos(v as i64))
        ));
    }
    l.push(format!("{i}  BULGULAR ({}):", m.findings.len()));
    if m.findings.is_empty() {
        l.push(format!(
            "{i}    Yok - çalışan istemcinin incelenen kodunda hile / yasaklı işlev bulunmadı."
        ));
    }
    let mut fs = m.findings.clone();
    fs.sort_by_key(|f| std::cmp::Reverse(f.rank));
    for f in &fs {
        l.push(format!("{i}    [{}] {}", goster_buyuk(&rank_verdict(f.rank)), f.title));
        l.push(format!("{i}        {}", f.detail));
        if !f.path.is_empty() {
            l.push(format!("{i}        Yol: {}", f.path));
        }
    }
    for n in &m.notes {
        l.push(format!("{i}  Not: {n}"));
    }
    l.push(format!("{i}  Komut satırı (gizli bilgiler maskelendi):"));
    l.push(format!("{i}    {}", uslice(&m.cmdline, 3000)));
    l
}

pub fn active_lines(r: &ClientResult) -> StrList {
    let mut l: StrList = Vec::new();
    l.push(format!(
        "Taranan süreç: {}  |  Minecraft: {}  |  diğer Java: {}  |  enjektör bulgusu: {}",
        r.process_count,
        r.minecraft.len(),
        r.other_java.len(),
        r.injectors.len()
    ));
    for m in &r.minecraft {
        l.push(String::new());
        l.extend(client_lines(m, ""));
    }
    for o in &r.other_java {
        if o.rank <= 0 {
            continue;
        }
        l.push(String::new());
        l.push(format!(
            "[{}] Minecraft dışı Java süreci PID {}: {}",
            o.verdict, o.pid, o.exe
        ));
        l.push(format!("  Giriş: {}", if o.main.is_empty() { "-" } else { &o.main }));
        for h in &o.hits {
            l.push(format!("  - {}: {}", h.file, join(&finding_labels(h, 4), "; ")));
        }
    }
    let mut others: StrList = Vec::new();
    for o in &r.other_java {
        if o.rank == 0 && others.len() < 8 {
            others.push(format!("PID {} {}", o.pid, path_basename(&o.exe)));
        }
    }
    if !others.is_empty() {
        l.push(String::new());
        l.push(format!("Diğer Java süreçleri (temiz): {}", join(&others, ", ")));
    }
    for i in &r.injectors {
        l.push(String::new());
        l.push(format!(
            "[{}] Çalışan program Java'ya kod enjekte edebiliyor / gizli kod taşıyor: PID {}  {}",
            rank_verdict(i.rank),
            i.pid,
            i.path
        ));
        l.push(format!("  {}", i.detail));
    }
    for n in &r.notes {
        l.push(format!("Not: {n}"));
    }
    for e in &r.errors {
        l.push(format!("Hata: {e}"));
    }
    l
}

pub fn rank_verdict(r: i32) -> String {
    verdict_by_rank(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> StrList {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn split_basit() {
        assert_eq!(split_cmdline("a b  c"), v(&["a", "b", "c"]));
        assert_eq!(split_cmdline("  "), Vec::<String>::new());
    }

    #[test]
    fn split_tirnak() {
        assert_eq!(
            split_cmdline("\"C:\\Program Files\\x.exe\" -cp a"),
            v(&["C:\\Program Files\\x.exe", "-cp", "a"])
        );
        assert_eq!(split_cmdline("a\"\" b"), v(&["a", "b"]));
        assert_eq!(split_cmdline("\"\""), v(&[""]));
    }

    #[test]
    fn split_ters_bolu() {
        assert_eq!(split_cmdline("a\\\\\"b c\" d"), v(&["a\\b c", "d"]));
        assert_eq!(split_cmdline("a\\\"b c"), v(&["a\"b", "c"]));
        assert_eq!(split_cmdline("C:\\dir\\ x"), v(&["C:\\dir\\", "x"]));
    }

    #[test]
    fn split_cift_tirnak_icinde() {
        assert_eq!(split_cmdline("\"a \"\"b\"\" c\""), v(&["a \"b\" c"]));
    }

    #[test]
    fn javacmd_prop() {
        let j = JavaCmd {
            props: vec![("a".into(), "1".into()), ("a".into(), "2".into())],
            ..Default::default()
        };
        assert_eq!(j.prop("a"), "2");
        assert!(j.has_prop("a"));
        assert!(!j.has_prop("b"));
        assert_eq!(j.prop("b"), "");
    }

    #[test]
    fn kv_ayirma() {
        assert_eq!(kv_split("a=b=c"), ("a".to_string(), "b=c".to_string()));
        assert_eq!(kv_split("abc"), ("abc".to_string(), String::new()));
    }

    #[test]
    fn varsayilanlar() {
        assert_eq!(ClientResult::default().verdict, "TEMIZ");
        assert_eq!(Injector::default().rank, 3);
    }

    #[test]
    fn ana_sinif_adlari() {
        assert_eq!(
            main_class_name("net.fabricmc.loader.impl.launch.knot.KnotClient"),
            "Fabric"
        );
        assert_eq!(main_class_name("x"), "");
    }

    #[test]
    fn java_cmdline_ayristirma() {
        let argv = split_cmdline(
            "javaw.exe -Xmx2G -Dminecraft.launcher.brand=x -javaagent:a.jar=opt -cp a.jar;b.jar net.minecraft.client.main.Main --username Foo",
        );
        let j = parse_java_cmdline(&argv);
        assert_eq!(j.main, "net.minecraft.client.main.Main");
        assert_eq!(j.cp, v(&["a.jar", "b.jar"]));
        assert_eq!(j.agents[0].path, "a.jar");
        assert_eq!(j.agents[0].options, "opt");
        assert_eq!(game_arg(&j.game_args, "--username"), "Foo");
        assert_eq!(j.prop("minecraft.launcher.brand"), "x");
    }
}
