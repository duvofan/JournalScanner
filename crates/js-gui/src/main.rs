#![windows_subsystem = "windows"]

mod api;
mod app;
mod crash;
mod export;
mod model;
mod pages;
mod scans;
mod shot;
mod theme;
mod widgets;

#[global_allocator]
static AYIRICI: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn load_icon() -> Option<egui::IconData> {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")).ok()
}

extern "C" {
    fn mi_option_set(option: i32, value: std::ffi::c_long);
}

fn main() -> eframe::Result {
    // SAFETY: seçenek numarası geçerli.
    unsafe { mi_option_set(15, 0) };
    let args: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    if args.get(1).is_some_and(|a| a.eq_ignore_ascii_case("--avdll")) {
        let code = std::thread::Builder::new()
            .stack_size(16 << 20)
            .spawn(move || js_native::run(args))
            .map(|h| h.join().unwrap_or(1))
            .unwrap_or(1);
        std::process::exit(code);
    }
    crash::kur();
    let mut viewport = egui::ViewportBuilder::default()
        .with_title(concat!("JournalScanner v", env!("CARGO_PKG_VERSION")))
        .with_inner_size([1440.0, 860.0])
        .with_min_inner_size([880.0, 520.0]);
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }
    let secenekler = eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Glow,
        multisampling: 0,
        depth_buffer: 0,
        stencil_buffer: 0,
        ..Default::default()
    };
    let sonuc = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        eframe::run_native(
            "JournalScanner",
            secenekler,
            Box::new(|cc| {
                let app = app::App::new(cc);
                crash::test_tetikle(true);
                Ok(Box::new(app))
            }),
        )
    }));
    if matches!(sonuc, Ok(Ok(()))) {
        return Ok(());
    }
    hata_kutusu();
    std::process::exit(1);
}

fn hata_kutusu() {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};
    let w = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (t, m) = (
        w("JournalScanner"),
        w("OpenGL açılamadı.

Ekran kartı sürücüsünü güncelleyin ve programı yeniden başlatın."),
    );
    // SAFETY: iki dizge de NUL ile biten, çağrı süresince yaşayan UTF-16 arabelleklerdir.
    unsafe {
        MessageBoxW(None, PCWSTR(m.as_ptr()), PCWSTR(t.as_ptr()), MB_OK | MB_ICONERROR);
    }
}
