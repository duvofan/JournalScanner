use js_core::client::{active_lines, scan_active_clients};
use js_core::devices::scan_devices;
use js_core::disk::DiskScanner;
use js_core::events::scan_ntfs_events;
use js_core::jar::{scan_directory, scan_jar, scan_jar_bytes, ScanResult};
use js_core::learn::{learn_export_lines, learn_from_result, learn_path, learn_save};
use js_core::logs::{auto_mod_dirs, launcher_log_dirs, scan_logs};
use js_core::prefetch::{parse_prefetch_bytes, scan_prefetch, Prefetch};
use js_core::report::{build_disk_report, build_report, mod_lines};
use js_core::util::{env, is_dir, path_basename, path_join_all, read_file};
use std::io::Write;

#[global_allocator]
static AYIRICI: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn jesc(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                o.push('\\');
                o.push(c);
            }
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn res_json(r: &ScanResult) -> String {
    let mut keys: Vec<&str> = r.findings.iter().map(|f| f.key.as_str()).collect();
    keys.sort();
    let mut o = format!(
        "{{\"file\":{},\"verdict\":{},\"rank\":{},\"classes\":{},\"keys\":[",
        jesc(&r.file),
        jesc(&r.verdict),
        r.rank,
        r.class_count
    );
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&jesc(k));
    }
    o.push_str("],\"nested\":[");
    for (i, n) in r.nested.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        o.push_str(&res_json(n));
    }
    o.push_str("]}");
    o
}

fn out(s: &str) {
    let so = std::io::stdout();
    let mut h = so.lock();
    let mut buf = s.replace('\n', "\r\n");
    buf.push_str("\r\n");
    let _ = h.write_all(buf.as_bytes());
    let _ = h.flush();
}

fn run(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("kullanım: jscli jar <dosya...>");
        return 2;
    }
    let cmd = args[1].as_str();
    match cmd {
        "jar" => {
            for a in &args[2..] {
                out(&res_json(&scan_jar(a)));
            }
            0
        }
        "jardisk" => {
            for a in &args[2..] {
                let Some(d) = read_file(a, -1, 0) else { continue };
                out(&res_json(&scan_jar_bytes(&path_basename(a), &d, 0, a, true, None)));
            }
            0
        }
        "disk" => {
            let roots: Vec<String> = args[2..].to_vec();
            let mut ds = DiskScanner::new(roots, None, None, 0, Vec::new());
            let d = ds.run();
            for r in &d.results {
                let mut j = res_json(r);
                j.pop();
                j.push_str(",\"also\":[");
                for (i, a) in r.also_at.iter().enumerate() {
                    if i > 0 {
                        j.push(',');
                    }
                    j.push_str(&jesc(a));
                }
                j.push_str("]}");
                out(&j);
            }
            let s = &d.stats;
            eprintln!(
                "files={} dirs={} archives={} texts={} denied={} flagged={} containers={} loose={} unopened={} {:.1}s",
                s.files,
                s.dirs,
                s.archives,
                s.texts,
                s.denied,
                s.flagged,
                s.containers,
                s.loose_groups,
                s.unopened,
                d.duration
            );
            0
        }
        "logs" => {
            let dirs: Vec<String> = args[2..].to_vec();
            let lr = scan_logs(
                5,
                "",
                if dirs.is_empty() { None } else { Some(dirs.as_slice()) },
                None,
                0.0,
            );
            for r in &lr.results {
                let mut j = format!(
                    "{{\"file\":{},\"verdict\":{},\"user\":{},\"mods\":{},\"hits\":[",
                    jesc(&r.file),
                    jesc(&r.verdict),
                    jesc(r.info.user.as_deref().unwrap_or("")),
                    r.mods_total
                );
                for (i, h) in r.hits.iter().enumerate() {
                    if i > 0 {
                        j.push(',');
                    }
                    j.push_str(&jesc(&format!("{}|{}|{}", h.r#mod.id, h.basis, h.category)));
                }
                j.push_str(&format!("],\"same\":{}}}", r.same_session.len()));
                out(&j);
            }
            eprintln!(
                "files={} results={} jars={} errors={}",
                lr.files.len(),
                lr.results.len(),
                lr.jars_checked,
                lr.errors.len()
            );
            0
        }
        "client" => {
            let prog = |m: &str| eprintln!("  .. {}", m);
            let r = scan_active_clients(Some(&prog), None, None);
            for l in active_lines(&r) {
                out(&l);
            }
            out(&format!("OVERALL {} {:.1}s", r.verdict, r.duration));
            0
        }
        "learn" => {
            let mut added = 0;
            for a in &args[2..] {
                if is_dir(a) {
                    let mut ds = DiskScanner::new(vec![a.clone()], None, None, 0, Vec::new());
                    let d = ds.run();
                    for r in &d.results {
                        added += learn_from_result(r, "Disk Taramasi");
                    }
                } else {
                    added += learn_from_result(&scan_jar(a), "Mod Taramasi");
                }
            }
            learn_save();
            out(&format!("eklenen/güncellenen: {}   hafıza: {}", added, learn_path()));
            for l in learn_export_lines() {
                out(&l);
            }
            0
        }
        "moddirs" => {
            for d in auto_mod_dirs(args.get(2).map(String::as_str).unwrap_or("")) {
                out(&format!("mods {}", d));
            }
            for d in launcher_log_dirs() {
                out(&format!("logs {}", d));
            }
            0
        }
        "modreport" => {
            for a in &args[2..] {
                for l in mod_lines(&scan_jar(a), "") {
                    out(&l);
                }
                out("");
            }
            0
        }
        "diskreport" => {
            let roots: Vec<String> = args[2..].to_vec();
            let mut ds = DiskScanner::new(roots, None, None, 0, Vec::new());
            out(&build_disk_report(&ds.run()).full);
            0
        }
        "pf" => {
            for a in &args[2..] {
                let raw = read_file(a, -1, 0);
                let mut pf = Prefetch::default();
                let mut err = String::new();
                let ok = match &raw {
                    Some(r) => parse_prefetch_bytes(r, &path_basename(a), &mut pf, &mut err),
                    None => false,
                };
                if !ok {
                    out(&format!("{} HATA {}", a, err));
                    continue;
                }
                out(&format!(
                    "{} v{} exe={} runs={} times={} files={} vols={}",
                    pf.name,
                    pf.version,
                    pf.exe,
                    pf.run_count,
                    pf.run_times.len(),
                    pf.filenames.len(),
                    pf.volumes.len()
                ));
            }
            0
        }
        "report" => {
            let mods = match args.get(2) {
                Some(m) => m.clone(),
                None => path_join_all(&[&env("APPDATA"), ".minecraft", "mods"]),
            };
            let mut jars: Vec<ScanResult> = if is_dir(&mods) {
                scan_directory(&mods, None, 0)
            } else {
                Vec::new()
            };
            for d in auto_mod_dirs(&mods) {
                jars.extend(scan_directory(&d, None, 0));
            }
            let ev = scan_ntfs_events(5);
            let pf = scan_prefetch(Some(&ev), None);
            let lr = scan_logs(5, &mods, None, None, 0.0);
            let dev = scan_devices(5, None);
            let cl = scan_active_clients(None, None, None);
            out(&build_report(&jars, &ev, &mods, Some(&pf), Some(&lr), Some(&dev), Some(&cl)).full);
            0
        }
        _ => {
            eprintln!("bilinmeyen komut: {}", cmd);
            2
        }
    }
}

extern "C" {
    fn mi_option_set(option: i32, value: std::ffi::c_long);
}

fn main() {
    // SAFETY: seçenek numarası geçerli; ilk ayırmalardan sonra çağrılması zararsızdır.
    unsafe { mi_option_set(15, 0) };
    let args: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    let code = std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(move || run(&args))
        .map(|h| h.join().unwrap_or(1))
        .unwrap_or(1);
    std::process::exit(code);
}
