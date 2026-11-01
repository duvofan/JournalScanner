use crate::util::*;
use std::collections::HashMap;
use std::io::Read;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Security::Cryptography::Catalog::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::WinTrust::*;
use windows::Win32::Security::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Threading::*;

pub fn wz(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn from_w(b: &[u16]) -> String {
    String::from_utf16_lossy(b)
}

pub fn lower_w(s: &str) -> String {
    s.to_lowercase()
}

pub fn get_env(name: &str) -> String {
    std::env::var_os(name)
        .map(|v| v.to_string_lossy().into_owned())
        .filter(|v| v.len() < 2048)
        .unwrap_or_default()
}

pub fn norm_path(p: &str) -> String {
    let mut p = p.to_string();
    if p.starts_with("\\\\?\\UNC\\") {
        p = format!("\\\\{}", &p[8..]);
    } else if p.starts_with("\\\\?\\") || p.starts_with("\\??\\") {
        p = p[4..].to_string();
    }
    if p.len() >= 12 && p.is_char_boundary(12) && lower_w(&p[..12]) == "\\systemroot\\" {
        let r = get_env("SystemRoot");
        if !r.is_empty() {
            p = format!("{}{}", r, &p[11..]);
        }
    }
    p.replace('/', "\\")
}

pub fn build_dev_map() -> Vec<(String, String)> {
    let mut v = Vec::new();
    let drives = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if drives & (1 << i) != 0 {
            let dl = [(b'A' + i as u8) as u16, b':' as u16, 0];
            let mut tgt = [0u16; 1024];
            let n = unsafe { QueryDosDeviceW(PCWSTR(dl.as_ptr()), Some(&mut tgt)) };
            if n > 0 {
                let end = tgt.iter().position(|&c| c == 0).unwrap_or(0);
                v.push((lower_w(&from_w(&tgt[..end])), from_w(&dl[..2])));
            }
        }
    }
    v
}

pub fn nt_to_dos(dev_map: &[(String, String)], nt: &str) -> String {
    let l = lower_w(nt);
    for (dev, dl) in dev_map {
        if l.len() >= dev.len()
            && l.starts_with(dev.as_str())
            && (l.len() == dev.len() || l.as_bytes()[dev.len()] == b'\\')
        {
            if let Some(rest) = nt.get(dev.len()..) {
                return format!("{}{}", dl, rest);
            }
        }
    }
    if l.starts_with("\\device\\mup\\") {
        if let Some(rest) = nt.get(12..) {
            return format!("\\\\{}", rest);
        }
    }
    norm_path(nt)
}

pub fn is_under(low_path: &str, low_dir: &str) -> bool {
    if low_dir.is_empty() || low_path.len() < low_dir.len() || !low_path.starts_with(low_dir) {
        return false;
    }
    low_path.len() == low_dir.len() || low_path.as_bytes()[low_dir.len()] == b'\\' || low_dir.ends_with('\\')
}

#[derive(Default, Clone)]
pub struct Dirs {
    pub user: String,
    pub downloads: String,
    pub desktop: String,
    pub documents: String,
    pub temp: String,
    pub local: String,
    pub roaming: String,
    pub prog_data: String,
    pub public: String,
    pub sysroot: String,
    pub pf: String,
    pub pf86: String,
    pub mc: String,
    pub self_exe: String,
}

pub fn init_dirs() -> Dirs {
    let l = |mut s: String| -> String {
        while s.len() > 3 && s.ends_with('\\') {
            s.pop();
        }
        lower_w(&norm_path(&s))
    };
    let mut d = Dirs {
        user: l(get_env("USERPROFILE")),
        ..Default::default()
    };
    d.downloads = format!("{}\\downloads", d.user);
    d.desktop = format!("{}\\desktop", d.user);
    d.documents = format!("{}\\documents", d.user);
    d.temp = l(get_env("TEMP"));
    d.local = l(get_env("LOCALAPPDATA"));
    d.roaming = l(get_env("APPDATA"));
    d.prog_data = l(get_env("ProgramData"));
    d.public = l(get_env("PUBLIC"));
    d.sysroot = l(get_env("SystemRoot"));
    d.pf = l(get_env("ProgramFiles"));
    d.pf86 = l(get_env("ProgramFiles(x86)"));
    d.mc = format!("{}\\.minecraft", d.roaming);
    if let Ok(p) = std::env::current_exe() {
        d.self_exe = lower_w(&norm_path(&p.to_string_lossy()));
    }
    d
}

pub fn in_user_drop_dir(d: &Dirs, path: &str) -> bool {
    let l = lower_w(path);
    is_under(&l, &d.downloads)
        || is_under(&l, &d.desktop)
        || is_under(&l, &d.documents)
        || is_under(&l, &d.temp)
        || is_under(&l, &d.public)
        || l.contains("\\$recycle.bin\\")
        || l.contains("\\onedrive\\")
}

pub fn long_path(p: &str) -> String {
    let b = p.as_bytes();
    if p.len() >= 240 && !p.starts_with("\\\\?\\") && p.len() > 2 && b[1] == b':' {
        return format!("\\\\?\\{}", p);
    }
    p.to_string()
}

pub fn read_file_all(path: &str, out: &mut Vec<u8>, max_bytes: u64, allow_partial: bool) -> (bool, bool) {
    out.clear();
    let Ok(f) = std::fs::File::open(long_path(path)) else {
        return (false, false);
    };
    let Ok(md) = f.metadata() else { return (false, false) };
    let sz = md.len();
    if sz == 0 || (sz > max_bytes && !allow_partial) {
        return (false, false);
    }
    let truncated = sz > max_bytes;
    let want = sz.min(max_bytes) as usize;
    out.resize(want, 0);
    let mut done = 0usize;
    let mut f = f;
    while done < want {
        let c = (want - done).min(16 << 20);
        match f.read(&mut out[done..done + c]) {
            Ok(0) | Err(_) => break,
            Ok(n) => done += n,
        }
    }
    out.truncate(done);
    (done > 0, truncated)
}

pub fn file_exists(p: &str) -> bool {
    std::fs::metadata(long_path(p)).map(|m| !m.is_dir()).unwrap_or(false)
}

pub fn base_name(p: &str) -> String {
    match p.rfind(['\\', '/']) {
        None => p.to_string(),
        Some(k) => p[k + 1..].to_string(),
    }
}

pub fn enable_debug_privilege() -> bool {
    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut tok).is_err() {
            return false;
        }
        let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        let name = wz("SeDebugPrivilege");
        if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name.as_ptr()), &mut tp.Privileges[0].Luid).is_err() {
            let _ = CloseHandle(tok);
            return false;
        }
        let ok = AdjustTokenPrivileges(
            tok,
            false,
            Some(&tp),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        );
        let e = GetLastError();
        let _ = CloseHandle(tok);
        ok.is_ok() && e == ERROR_SUCCESS
    }
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).is_err() {
            return false;
        }
        let mut te = TOKEN_ELEVATION::default();
        let mut rl = 0u32;
        let r = GetTokenInformation(
            tok,
            TokenElevation,
            Some(&mut te as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut rl,
        )
        .is_ok()
            && te.TokenIsElevated != 0;
        let _ = CloseHandle(tok);
        r
    }
}

pub type NtQip = unsafe extern "system" fn(HANDLE, u32, *mut core::ffi::c_void, u32, *mut u32) -> i32;
pub type NtQsi = unsafe extern "system" fn(u32, *mut core::ffi::c_void, u32, *mut u32) -> i32;
pub type NtQo = unsafe extern "system" fn(HANDLE, u32, *mut core::ffi::c_void, u32, *mut u32) -> i32;

#[derive(Default, Clone, Copy)]
pub struct NtFns {
    pub qip: Option<NtQip>,
    pub qit: Option<NtQip>,
    pub qsi: Option<NtQsi>,
    pub qo: Option<NtQo>,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct AvPbi {
    pub exit_status: i32,
    pub peb_base_address: usize,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub unique_process_id: usize,
    pub inherited_from: usize,
}

pub fn init_nt() -> NtFns {
    let mut f = NtFns::default();
    unsafe {
        let name = wz("ntdll.dll");
        let Ok(h) = GetModuleHandleW(PCWSTR(name.as_ptr())) else {
            return f;
        };
        f.qip = GetProcAddress(h, windows::core::s!("NtQueryInformationProcess"))
            .map(|p| std::mem::transmute::<_, NtQip>(p));
        f.qit = GetProcAddress(h, windows::core::s!("NtQueryInformationThread"))
            .map(|p| std::mem::transmute::<_, NtQip>(p));
        f.qsi = GetProcAddress(h, windows::core::s!("NtQuerySystemInformation"))
            .map(|p| std::mem::transmute::<_, NtQsi>(p));
        f.qo = GetProcAddress(h, windows::core::s!("NtQueryObject")).map(|p| std::mem::transmute::<_, NtQo>(p));
    }
    f
}

#[derive(Debug, Clone, Default)]
pub struct SigInfo {
    pub valid: bool,
    pub catalog: bool,
    pub trusted: bool,
    pub signer: String,
}

fn signer_from_state(st: HANDLE) -> String {
    unsafe {
        let pd = WTHelperProvDataFromStateData(st);
        if pd.is_null() {
            return String::new();
        }
        let sg = WTHelperGetProvSignerFromChain(pd, 0, false, 0);
        if sg.is_null() {
            return String::new();
        }
        let pc = WTHelperGetProvCertFromChain(sg, 0);
        if pc.is_null() || (*pc).pCert.is_null() {
            return String::new();
        }
        let mut nm = [0u16; 256];
        let n = CertGetNameStringW(&*(*pc).pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut nm));
        if n > 1 {
            let end = nm.iter().position(|&c| c == 0).unwrap_or(nm.len());
            from_w(&nm[..end])
        } else {
            String::new()
        }
    }
}

pub fn is_trusted_signer(signer: &str) -> bool {
    let l = lower_w(signer);
    const T: [&str; 52] = [
        "microsoft",
        "nvidia corporation",
        "advanced micro devices",
        "intel corporation",
        "realtek semiconductor",
        "asustek",
        "micro-star international",
        "discord inc",
        "medal",
        "obs project",
        "oracle america",
        "oracle corporation",
        "eclipse.org foundation",
        "eclipse foundation",
        "azul systems",
        "amazon.com services",
        "mojang",
        "valve corp",
        "logitech",
        "razer",
        "corsair",
        "steelseries",
        "overwolf",
        "a-volute",
        "nahimic",
        "google llc",
        "mozilla corporation",
        "adobe inc",
        "electronic arts",
        "epic games",
        "riot games",
        "blizzard entertainment",
        "ubisoft",
        "avast software",
        "kaspersky",
        "bitdefender",
        "malwarebytes",
        "eset, spol",
        "norton",
        "gen digital",
        "mcafee",
        "sophos",
        "symantec",
        "trend micro",
        "avira",
        "f-secure",
        "cisco systems",
        "vmware",
        "streamlabs",
        "elgato",
        "adoptium",
        "jetbrains",
    ];
    T.iter().any(|x| l.contains(x)) || l.contains("bellsoft") || l.contains("red hat")
}

unsafe fn wt_close(wd: &mut WINTRUST_DATA, act: &mut windows::core::GUID) {
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = WinVerifyTrust(
        HWND(-1isize as *mut core::ffi::c_void),
        act,
        wd as *mut _ as *mut core::ffi::c_void,
    );
}

const WTD_CACHE_ONLY_URL: u32 = 0x00001000;

pub fn verify_signature(path: &str) -> SigInfo {
    let mut si = SigInfo::default();
    let mut act = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let lp = wz(&long_path(path));
    unsafe {
        {
            let mut fi: WINTRUST_FILE_INFO = std::mem::zeroed();
            fi.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
            fi.pcwszFilePath = PCWSTR(lp.as_ptr());
            let mut wd: WINTRUST_DATA = std::mem::zeroed();
            wd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
            wd.dwUIChoice = WTD_UI_NONE;
            wd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wd.dwUnionChoice = WTD_CHOICE_FILE;
            wd.Anonymous.pFile = &mut fi;
            wd.dwStateAction = WTD_STATEACTION_VERIFY;
            wd.dwProvFlags = WINTRUST_DATA_PROVIDER_FLAGS(WTD_REVOCATION_CHECK_NONE.0 | WTD_CACHE_ONLY_URL);
            let st = WinVerifyTrust(
                HWND(-1isize as *mut core::ffi::c_void),
                &mut act,
                &mut wd as *mut _ as *mut core::ffi::c_void,
            );
            if st == 0 {
                si.valid = true;
                si.signer = signer_from_state(wd.hWVTStateData);
            }
            wt_close(&mut wd, &mut act);
            if si.valid {
                si.trusted = is_trusted_signer(&si.signer);
                return si;
            }
        }
        let Ok(hf) = CreateFileW(
            PCWSTR(lp.as_ptr()),
            0x8000_0000, // GENERIC_READ
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) else {
            return si;
        };
        for attempt in 0..2 {
            if si.valid {
                break;
            }
            let mut adm: isize = 0;
            let mut hash = [0u8; 128];
            let mut cb: u32 = hash.len() as u32;
            let got;
            let mut hh = false;
            if attempt == 0 {
                let alg = wz("SHA256");
                got = CryptCATAdminAcquireContext2(&mut adm, None, PCWSTR(alg.as_ptr()), None, None).is_ok();
                if got {
                    hh = CryptCATAdminCalcHashFromFileHandle2(adm, hf, &mut cb, Some(hash.as_mut_ptr()), None).is_ok();
                }
            } else {
                got = CryptCATAdminAcquireContext(&mut adm, None, None).is_ok();
                if got {
                    hh = CryptCATAdminCalcHashFromFileHandle(hf, &mut cb, Some(hash.as_mut_ptr()), None).as_bool();
                }
            }
            if !got {
                continue;
            }
            if hh && cb > 0 {
                let hx = b"0123456789ABCDEF";
                let mut tag: Vec<u16> = Vec::new();
                for i in 0..cb as usize {
                    tag.push(hx[(hash[i] >> 4) as usize] as u16);
                    tag.push(hx[(hash[i] & 15) as usize] as u16);
                }
                tag.push(0);
                let ci = CryptCATAdminEnumCatalogFromHash(adm, &hash[..cb as usize], None, None);
                if ci != 0 {
                    let mut cat: CATALOG_INFO = std::mem::zeroed();
                    cat.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
                    if CryptCATCatalogInfoFromContext(ci, &mut cat, 0).is_ok() {
                        let mut wci: WINTRUST_CATALOG_INFO = std::mem::zeroed();
                        wci.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
                        wci.pcwszCatalogFilePath = PCWSTR(cat.wszCatalogFile.as_ptr());
                        wci.pcwszMemberTag = PCWSTR(tag.as_ptr());
                        wci.pcwszMemberFilePath = PCWSTR(lp.as_ptr());
                        wci.hMemberFile = hf;
                        wci.pbCalculatedFileHash = hash.as_mut_ptr();
                        wci.cbCalculatedFileHash = cb;
                        wci.hCatAdmin = adm;
                        let mut wd: WINTRUST_DATA = std::mem::zeroed();
                        wd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
                        wd.dwUIChoice = WTD_UI_NONE;
                        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                        wd.dwUnionChoice = WTD_CHOICE_CATALOG;
                        wd.Anonymous.pCatalog = &mut wci;
                        wd.dwStateAction = WTD_STATEACTION_VERIFY;
                        wd.dwProvFlags = WINTRUST_DATA_PROVIDER_FLAGS(WTD_REVOCATION_CHECK_NONE.0 | WTD_CACHE_ONLY_URL);
                        let st = WinVerifyTrust(
                            HWND(-1isize as *mut core::ffi::c_void),
                            &mut act,
                            &mut wd as *mut _ as *mut core::ffi::c_void,
                        );
                        if st == 0 {
                            si.valid = true;
                            si.catalog = true;
                            si.signer = signer_from_state(wd.hWVTStateData);
                        }
                        wt_close(&mut wd, &mut act);
                    }
                    let _ = CryptCATAdminReleaseCatalogContext(adm, ci, 0);
                }
            }
            let _ = CryptCATAdminReleaseContext(adm, 0);
        }
        let _ = CloseHandle(hf);
    }
    if si.valid {
        si.trusted = is_trusted_signer(&si.signer);
    }
    si
}

pub fn sig_text(s: &SigInfo) -> String {
    if !s.valid {
        return "İMZASIZ veya geçersiz imza".to_string();
    }
    let t = format!(
        "geçerli imza ({}): {}",
        if s.catalog { "katalog" } else { "gömülü" },
        s.signer
    );
    format!(
        "{}{}",
        t,
        if s.trusted {
            "  [güvenilir yayıncı]"
        } else {
            "  [yayıncı listede yok]"
        }
    )
}

pub fn safe_name(s: &str) -> String {
    let mut o: String = s
        .bytes()
        .map(|c| {
            if is_alnum(c) || c == b'.' || c == b'-' {
                c as char
            } else {
                '_'
            }
        })
        .collect();
    if o.len() > 60 {
        o = o[o.len() - 60..].to_string();
    }
    o
}

pub fn write_text_file(path: &str, lines: &[String]) {
    let mut buf: Vec<u8> = Vec::new();
    for l in lines {
        buf.extend_from_slice(l.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    let _ = std::fs::write(path, buf);
}

pub fn addr_s(a: u64) -> String {
    format!("0x{:X}", a)
}

pub struct SigCache {
    map: HashMap<String, SigInfo>,
}
impl SigCache {
    pub fn new() -> Self {
        SigCache { map: HashMap::new() }
    }
    pub fn verify_cached(&mut self, path: &str) -> SigInfo {
        let k = lower_w(path);
        if let Some(s) = self.map.get(&k) {
            return s.clone();
        }
        let s = verify_signature(path);
        self.map.insert(k, s.clone());
        s
    }
}

impl Default for SigCache {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
pub fn pwstr_null() -> PWSTR {
    PWSTR::null()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(norm_path("\\\\?\\C:\\a/b"), "C:\\a\\b");
        assert_eq!(norm_path("\\\\?\\UNC\\srv\\x"), "\\\\srv\\x");
        assert!(is_under("c:\\users\\a\\downloads\\x", "c:\\users\\a\\downloads"));
        assert!(!is_under("c:\\users\\a\\downloadsx", "c:\\users\\a\\downloads"));
        assert_eq!(base_name("C:\\a\\b.dll"), "b.dll");
    }
    #[test]
    fn trusted() {
        assert!(is_trusted_signer("Microsoft Windows"));
        assert!(is_trusted_signer("Red Hat, Inc."));
        assert!(!is_trusted_signer("Evil Corp"));
    }
    #[test]
    fn safe() {
        assert_eq!(safe_name("a b.dll"), "a_b.dll");
    }
}
