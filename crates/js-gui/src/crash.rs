use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HANDLE, HMODULE, HWND, LPARAM, WPARAM};
use windows::Win32::System::Diagnostics::Debug::{
    RtlCaptureContext, RtlLookupFunctionEntry, RtlVirtualUnwind, SetUnhandledExceptionFilter, CONTEXT,
    CONTEXT_FULL_AMD64, EXCEPTION_POINTERS, UNW_FLAG_NHANDLER,
};
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
};
use windows::Win32::System::Threading::{
    GetCurrentThreadId, OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_SUSPEND_RESUME,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumThreadWindows, IsWindow, IsWindowVisible, MessageBoxW, SendMessageTimeoutW, MB_ICONERROR, MB_OK, MB_TOPMOST,
    SMTO_ABORTIFHUNG, SMTO_BLOCK, WM_NULL,
};

const SURUM: &str = env!("CARGO_PKG_VERSION");
const DOSYA: &str = "JournalScanner_hata_raporu.txt";
const AZAMI_CERCEVE: usize = 48;

static ANA_IS: AtomicU32 = AtomicU32::new(0);
static RAPOR_KILIT: Mutex<()> = Mutex::new(());
static COKTU: AtomicBool = AtomicBool::new(false);

pub fn kur() {
    // SAFETY: GetCurrentThreadId yan etkisizdir.
    ANA_IS.store(unsafe { GetCurrentThreadId() }, Ordering::SeqCst);
    // SAFETY: filtre işlevi 'static ve iş parçacığı güvenli (yalnızca dosyaya yazar, MessageBox gösterir).
    unsafe {
        SetUnhandledExceptionFilter(Some(cokme_filtresi));
    }
    let onceki = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |bilgi| {
        panik_raporu(bilgi);
        onceki(bilgi);
    }));
    donma_bekcisi();
}

#[cfg(target_arch = "x86_64")]
fn cerceveler(mut c: CONTEXT) -> Vec<u64> {
    let mut out = Vec::with_capacity(AZAMI_CERCEVE);
    while out.len() < AZAMI_CERCEVE && c.Rip != 0 {
        out.push(c.Rip);
        let mut taban = 0u64;
        // SAFETY: c geçerli bir CONTEXT; işlev tablosu sorgusu ve çözme yalnızca okuma yapar.
        unsafe {
            let fe = RtlLookupFunctionEntry(c.Rip, &mut taban, None);
            if !fe.is_null() {
                let mut hd: *mut core::ffi::c_void = std::ptr::null_mut();
                let mut ef = 0u64;
                RtlVirtualUnwind(UNW_FLAG_NHANDLER, taban, c.Rip, fe, &mut c, &mut hd, &mut ef, None);
            } else {
                let mut ret = 0u64;
                let mut okunan = 0usize;
                let ok = windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
                    windows::Win32::System::Threading::GetCurrentProcess(),
                    c.Rsp as *const core::ffi::c_void,
                    &mut ret as *mut u64 as *mut core::ffi::c_void,
                    8,
                    Some(&mut okunan),
                );
                if ok.is_err() || okunan != 8 {
                    break;
                }
                c.Rip = ret;
                c.Rsp += 8;
            }
        }
    }
    out
}

#[cfg(not(target_arch = "x86_64"))]
fn cerceveler(_c: CONTEXT) -> Vec<u64> {
    Vec::new()
}

fn simdiki_cerceveler() -> Vec<u64> {
    let mut c = CONTEXT::default();
    // SAFETY: RtlCaptureContext verilen yapıyı doldurur.
    unsafe { RtlCaptureContext(&mut c) };
    cerceveler(c)
}

fn adres(a: u64) -> String {
    let mut m = HMODULE::default();
    // SAFETY: FROM_ADDRESS ile adres yalnızca modül aramasında kullanılır; refcount değişmez.
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(a as usize as *const u16),
            &mut m,
        )
    };
    if ok.is_ok() && !m.is_invalid() {
        let mut yol = [0u16; 260];
        // SAFETY: tampon boyutu doğru verilir.
        let n = unsafe { GetModuleFileNameW(Some(m), &mut yol) } as usize;
        if n > 0 {
            let tam = String::from_utf16_lossy(&yol[..n]);
            let ad = tam.rsplit(['\\', '/']).next().unwrap_or(&tam).to_string();
            return format!("{}+0x{:x}", ad, a.wrapping_sub(m.0 as u64));
        }
    }
    format!("0x{a:x}")
}

fn windows_surumu() -> String {
    #[repr(C)]
    struct OsVer {
        boyut: u32,
        ana: u32,
        alt: u32,
        derleme: u32,
        platform: u32,
        csd: [u16; 128],
    }
    type RtlGetVersion = unsafe extern "system" fn(*mut OsVer) -> i32;
    // SAFETY: ntdll her süreçte yüklüdür; RtlGetVersion imzası belgelendiği gibidir.
    unsafe {
        if let Ok(nt) = GetModuleHandleW(w!("ntdll.dll")) {
            if let Some(f) = GetProcAddress(nt, windows::core::s!("RtlGetVersion")) {
                let f: RtlGetVersion = std::mem::transmute(f);
                let mut v = OsVer {
                    boyut: std::mem::size_of::<OsVer>() as u32,
                    ana: 0,
                    alt: 0,
                    derleme: 0,
                    platform: 0,
                    csd: [0; 128],
                };
                if f(&mut v) == 0 {
                    return format!("Windows {}.{} build {}", v.ana, v.alt, v.derleme);
                }
            }
        }
    }
    "Windows (sürüm alınamadı)".to_string()
}

fn rapor_yolu() -> PathBuf {
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        let p = dir.join(DOSYA);
        if OpenOptions::new().append(true).create(true).open(&p).is_ok() {
            return p;
        }
    }
    std::env::temp_dir().join(DOSYA)
}

fn rapor_yaz(tur: &str, ayrinti: &str, cerceve: &[u64]) -> PathBuf {
    let _k = RAPOR_KILIT.lock().unwrap_or_else(|e| e.into_inner());
    let simdi = chrono_yok_yerel_saat();
    let mut t = String::new();
    t.push_str("==============================================================================\r\n");
    t.push_str(&format!("{tur}  -  {simdi}\r\n"));
    t.push_str(&format!("Program : JournalScanner v{SURUM} (Rust)\r\n"));
    t.push_str(&format!("Sistem  : {}\r\n", windows_surumu()));
    t.push_str(&format!("Ayrıntı : {}\r\n", ayrinti.replace('\n', "\r\n          ")));
    t.push_str("Çağrı zinciri (en üstteki hatanın olduğu yer):\r\n");
    for (i, a) in cerceve.iter().enumerate() {
        t.push_str(&format!("  #{i:02}  {}\r\n", adres(*a)));
    }
    t.push_str(
        "\r\nBu dosyayı geliştiriciye gönderin (kişisel bilgi içermez: yalnızca kod adresleri ve sürümler).\r\n\r\n",
    );
    let p = rapor_yolu();
    if let Ok(mut f) = OpenOptions::new().append(true).create(true).open(&p) {
        let _ = f.write_all(t.as_bytes());
    }
    p
}

fn chrono_yok_yerel_saat() -> String {
    js_core::util::fmt_local(js_core::util::now_epoch(), "%Y-%m-%d %H:%M:%S")
}

fn uyari_goster(yol: &std::path::Path) {
    let msg = format!(
        "JournalScanner beklenmedik bir hatayla kapanmak zorunda.\n\nHata raporu kaydedildi:\n{}\n\nLütfen bu dosyayı geliştiriciye gönderin.",
        yol.display()
    );
    if std::env::var_os("JS_HATA_SESSIZ").is_some() {
        return; // otomatik testlerde uyarı penceresi açılmasın
    }
    let m: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: m sıfırla biten UTF-16 dizgi.
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(m.as_ptr()),
            w!("JournalScanner - hata"),
            MB_OK | MB_ICONERROR | MB_TOPMOST,
        );
    }
}

unsafe extern "system" fn cokme_filtresi(ep: *const EXCEPTION_POINTERS) -> i32 {
    const EXECUTE_HANDLER: i32 = 1;
    if COKTU.swap(true, Ordering::SeqCst) {
        return EXECUTE_HANDLER;
    }
    let mut fr = Vec::new();
    let mut kod = 0u32;
    let mut yer = 0u64;
    let mut ek = String::new();
    if let Some(ep) = ep.as_ref() {
        if let Some(c) = ep.ContextRecord.as_ref() {
            fr = cerceveler(*c);
        }
        if let Some(r) = ep.ExceptionRecord.as_ref() {
            kod = r.ExceptionCode.0 as u32;
            yer = r.ExceptionAddress as u64;
            if kod == 0xC000_0005 && r.NumberParameters >= 2 {
                let tur = if r.ExceptionInformation[0] != 0 {
                    "yazma"
                } else {
                    "okuma"
                };
                ek = format!(" ({tur} 0x{:x})", r.ExceptionInformation[1]);
            }
        }
    }
    let det = format!(
        "istisna 0x{kod:08X}, adres {}, iş parçacığı {}{ek}",
        adres(yer),
        GetCurrentThreadId()
    );
    let p = rapor_yaz("ÇÖKME", &det, &fr);
    uyari_goster(&p);
    EXECUTE_HANDLER
}

fn panik_raporu(bilgi: &std::panic::PanicHookInfo<'_>) {
    let mesaj = if let Some(s) = bilgi.payload().downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = bilgi.payload().downcast_ref::<String>() {
        s.clone()
    } else {
        "(mesaj yok)".to_string()
    };
    let yer = bilgi
        .location()
        .map(|l| format!("{}:{}", l.file(), l.line()))
        .unwrap_or_default();
    // SAFETY: yan etkisiz sorgu.
    let is = unsafe { GetCurrentThreadId() };
    let ana = is == ANA_IS.load(Ordering::SeqCst);
    let tur = if ana {
        "ÇÖKME (arayüzde Rust panic'i)"
    } else {
        "HATA (tarama iş parçacığında Rust panic'i, yakalandı)"
    };
    let det = format!("{mesaj}\nkonum: {yer}, iş parçacığı {is}");
    let p = rapor_yaz(tur, &det, &simdiki_cerceveler());
    if ana && !COKTU.swap(true, Ordering::SeqCst) {
        uyari_goster(&p);
    }
}

fn donma_bekcisi() {
    let tid = ANA_IS.load(Ordering::SeqCst);
    let _ = std::thread::Builder::new().name("donma-bekcisi".into()).spawn(move || {
        // SAFETY: yalnızca askıya alma / bağlam okuma hakları istenir; tutamaç sonunda kapatılır.
        let th: Option<HANDLE> = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                false,
                tid,
            )
        }
        .ok();
        let mut hwnd: Option<HWND> = None;
        let mut raporlandi = false;
        loop {
            std::thread::sleep(Duration::from_secs(2));
            if hwnd.is_none_or(|h| !unsafe { IsWindow(Some(h)) }.as_bool()) {
                hwnd = ana_pencere(tid);
                if hwnd.is_none() {
                    continue;
                }
            }
            let Some(h) = hwnd else { continue };
            let mut r = 0usize;
            // SAFETY: h geçerli bir pencere; WM_NULL yan etkisizdir.
            let yanit = unsafe {
                SendMessageTimeoutW(
                    h,
                    WM_NULL,
                    WPARAM(0),
                    LPARAM(0),
                    SMTO_ABORTIFHUNG | SMTO_BLOCK,
                    10_000,
                    Some(&mut r),
                )
            };
            if yanit.0 != 0 {
                raporlandi = false; // yanıt verdi: bir sonraki donma yeniden raporlanır
                continue;
            }
            if raporlandi || !unsafe { IsWindow(Some(h)) }.as_bool() {
                continue;
            }
            raporlandi = true;
            let mut fr = Vec::new();
            if let Some(th) = th {
                // SAFETY: iş parçacığı askıya alınır, bağlamı okunur ve hemen devam ettirilir.
                unsafe {
                    if SuspendThread(th) != u32::MAX {
                        let mut c = CONTEXT {
                            ContextFlags: CONTEXT_FULL_AMD64,
                            ..Default::default()
                        };
                        if windows::Win32::System::Diagnostics::Debug::GetThreadContext(th, &mut c).is_ok() {
                            fr = cerceveler(c);
                        }
                        ResumeThread(th);
                    }
                }
            }
            rapor_yaz(
                "DONMA (arayüz 10 sn'den uzun yanıt vermedi)",
                &format!("arayüz iş parçacığı {tid}"),
                &fr,
            );
        }
    });
}

fn ana_pencere(tid: u32) -> Option<HWND> {
    unsafe extern "system" fn bul(h: HWND, l: LPARAM) -> windows::core::BOOL {
        // SAFETY: l, ana_pencere'deki yerel Option<HWND>'yi gösterir.
        unsafe {
            if IsWindowVisible(h).as_bool() {
                *(l.0 as *mut Option<HWND>) = Some(h);
                return false.into();
            }
        }
        true.into()
    }
    let mut sonuc: Option<HWND> = None;
    // SAFETY: geri çağırma yalnızca yukarıdaki yerel değişkene yazar ve EnumThreadWindows dönmeden biter.
    unsafe {
        let _ = EnumThreadWindows(tid, Some(bul), LPARAM(&mut sonuc as *mut Option<HWND> as isize));
    }
    sonuc
}

pub fn test_tetikle(asama_pencere: bool) {
    let Ok(t) = std::env::var("JS_HATA_TEST") else { return };
    match (t.as_str(), asama_pencere) {
        ("panik", true) => panic!("JS_HATA_TEST: bilerek tetiklenen panic"),
        ("erisim", true) => {
            // SAFETY: bilerek geçersiz adres okunur (yalnızca test).
            let v = unsafe { std::ptr::read_volatile(std::hint::black_box(16usize) as *const u64) };
            std::hint::black_box(v);
        }
        ("donma", true) => std::thread::sleep(Duration::from_secs(15)),
        _ => {}
    }
}
