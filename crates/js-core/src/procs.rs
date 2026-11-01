use crate::client::ProcInfo;
use crate::json::{json_parse, jstr};
use crate::util::*;
use std::collections::BTreeMap;

pub fn list_processes() -> Vec<ProcInfo> {
    #[cfg(windows)]
    {
        let out = list_win();
        if out.iter().any(|p| !p.cmdline.is_empty()) {
            return out;
        }
        let ps = list_powershell();
        if ps.is_empty() {
            out
        } else {
            ps
        }
    }
    #[cfg(not(windows))]
    {
        list_proc_fs()
    }
}

pub fn window_titles() -> BTreeMap<u32, StrList> {
    let mut out: BTreeMap<u32, StrList> = BTreeMap::new();
    #[cfg(windows)]
    {
        use windows::core::BOOL;
        use windows::Win32::Foundation::{HWND, LPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
        };
        unsafe extern "system" fn enum_cb(hwnd: HWND, lp: LPARAM) -> BOOL {
            // SAFETY: lp, EnumWindows çağrısında verilen &mut BTreeMap işaretçisidir.
            let out = unsafe { &mut *(lp.0 as *mut BTreeMap<u32, StrList>) };
            unsafe {
                if !IsWindowVisible(hwnd).as_bool() {
                    return BOOL(1);
                }
                let ln = GetWindowTextLengthW(hwnd);
                if ln <= 0 {
                    return BOOL(1);
                }
                let mut buf = vec![0u16; ln as usize + 1];
                let got = GetWindowTextW(hwnd, &mut buf);
                let mut pid = 0u32;
                GetWindowThreadProcessId(hwnd, Some(&mut pid));
                if got > 0 {
                    out.entry(pid).or_default().push(narrow(&buf[..got as usize]));
                }
            }
            BOOL(1)
        }
        // SAFETY: geri çağrı yalnızca bu çağrı sürerken çalışır; out bu sürede yaşar.
        unsafe {
            let _ = EnumWindows(Some(enum_cb), LPARAM(&mut out as *mut _ as isize));
        }
    }
    out
}

#[cfg(windows)]
fn ft_to(f: &windows::Win32::Foundation::FILETIME) -> Option<f64> {
    let v = ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
    filetime_to_epoch(v)
}

#[cfg(windows)]
type NtQip = unsafe extern "system" fn(isize, i32, *mut core::ffi::c_void, u32, *mut u32) -> i32;

#[cfg(windows)]
fn list_win() -> Vec<ProcInfo> {
    use windows::core::{s, w};
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut procs: Vec<ProcInfo> = Vec::new();
    // SAFETY: Toolhelp anlık görüntüsü; tutamaç sonunda kapatılır.
    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return procs,
        };
        let mut e = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                let n = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
                procs.push(ProcInfo {
                    pid: e.th32ProcessID,
                    ppid: e.th32ParentProcessID,
                    name: narrow(&e.szExeFile[..n]),
                    ..Default::default()
                });
                if Process32NextW(snap, &mut e).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    // SAFETY: ntdll.dll her zaman yüklüdür; işlev adresi imzası bilinen NtQueryInformationProcess'tir.
    let nq: Option<NtQip> = unsafe {
        GetModuleHandleW(w!("ntdll.dll"))
            .ok()
            .and_then(|m| GetProcAddress(m, s!("NtQueryInformationProcess")))
            .map(|f| std::mem::transmute::<unsafe extern "system" fn() -> isize, NtQip>(f))
    };
    for p in procs.iter_mut() {
        if p.pid == 0 || p.pid == 4 {
            continue;
        }
        // SAFETY: tutamak yalnızca bu döngü adımında kullanılır ve kapatılır.
        unsafe {
            let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, p.pid) {
                Ok(h) => h,
                Err(_) => continue,
            };
            let mut buf = vec![0u16; 32768];
            let mut sz = 32768u32;
            if QueryFullProcessImageNameW(
                h,
                PROCESS_NAME_FORMAT(0),
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut sz,
            )
            .is_ok()
            {
                p.path = narrow(&buf[..(sz as usize).min(buf.len())]);
            }
            let (mut c, mut x, mut k, mut u) = (
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
                FILETIME::default(),
            );
            if GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u).is_ok() {
                p.created = ft_to(&c);
            }
            if let Some(nq) = nq {
                let hv = h.0 as isize;
                let mut ret = 0u32;
                nq(hv, 60, std::ptr::null_mut(), 0, &mut ret);
                if ret > 0 && ret < 1_000_000 {
                    let words = (ret as usize + 16).div_ceil(8);
                    let mut cb = vec![0u64; words];
                    let total = words * 8;
                    let r = nq(
                        hv,
                        60,
                        cb.as_mut_ptr() as *mut _,
                        (ret + 16).min(total as u32),
                        &mut ret,
                    );
                    if r == 0 {
                        let base = cb.as_ptr() as usize;
                        let length = *(base as *const u16) as usize;
                        let bufp = *((base + 8) as *const usize);
                        let sz_total = (ret as usize + 16).min(total);
                        if bufp >= base && bufp + length <= base + sz_total {
                            let units = std::slice::from_raw_parts(bufp as *const u16, length / 2);
                            p.cmdline = narrow(units);
                        }
                    }
                }
            }
            let _ = CloseHandle(h);
        }
    }
    procs
}

#[cfg(windows)]
fn list_powershell() -> Vec<ProcInfo> {
    use std::io::Read;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let mut out: Vec<ProcInfo> = Vec::new();
    let cmd = "-NoProfile -NonInteractive -Command \"[Console]::OutputEncoding=[Text.Encoding]::UTF8; \
        Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,\
        @{n='C';e={$_.CreationDate.ToUniversalTime().ToString('o')}} | ConvertTo-Json -Compress\"";
    let mut child = match Command::new("powershell")
        .raw_arg(cmd)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return out,
    };
    let mut so = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(s) = so.as_mut() {
            let _ = s.read_to_end(&mut b);
        }
        b
    });
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(_) => break,
        }
        if start.elapsed() > Duration::from_millis(90000) {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.wait();
    let o = reader.join().unwrap_or_default();
    let j = match json_parse(&pystrip(&utf8_decode(&o, 0))) {
        Some(j) => j,
        None => return out,
    };
    let mut items: Vec<&crate::json::JVal> = Vec::new();
    if j.is_obj() {
        items.push(&j);
    } else if j.is_arr() {
        for x in &j.arr {
            items.push(x);
        }
    }
    for it in items {
        let mut p = ProcInfo::default();
        if let Some(v) = it.get("ProcessId") {
            if v.is_int() {
                p.pid = v.i as u32;
            }
        }
        if let Some(v) = it.get("ParentProcessId") {
            if v.is_int() {
                p.ppid = v.i as u32;
            }
        }
        p.name = jstr(it.get("Name"));
        p.path = jstr(it.get("ExecutablePath"));
        p.cmdline = jstr(it.get("CommandLine"));
        let c = jstr(it.get("C"));
        if !c.is_empty() {
            p.created = parse_utc_iso(&c);
        }
        out.push(p);
    }
    out
}

#[cfg(not(windows))]
fn list_proc_fs() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    for d in listdir_names("/proc") {
        if !is_digits(&d) {
            continue;
        }
        let cl = read_file(&format!("/proc/{d}/cmdline"), -1, 0);
        let st = read_file(&format!("/proc/{d}/stat"), -1, 0);
        let (cl, st) = match (cl, st) {
            (Some(a), Some(b)) => (a, b),
            _ => continue,
        };
        let mut p = ProcInfo {
            pid: d.parse().unwrap_or(0),
            ..Default::default()
        };
        for a in cl.split(|&b| b == 0) {
            if !a.is_empty() {
                p.argv.push(utf8_decode(a, 0));
            }
        }
        let stt = String::from_utf8_lossy(&st).into_owned();
        let rp = match stt.rfind(')') {
            Some(i) => i,
            None => continue,
        };
        let parts = split_ws(&stt[rp + 1..]);
        if parts.len() < 2 {
            continue;
        }
        p.ppid = parts[1].parse().unwrap_or(0);
        p.path = match std::fs::read_link(format!("/proc/{d}/exe")) {
            Ok(l) => l.to_string_lossy().into_owned(),
            Err(_) => p.argv.first().cloned().unwrap_or_default(),
        };
        p.name = path_basename(&p.path);
        let q: StrList = p
            .argv
            .iter()
            .map(|a| if has(a, " ") { format!("\"{a}\"") } else { a.clone() })
            .collect();
        p.cmdline = join(&q, " ");
        out.push(p);
    }
    out
}
