use embed_manifest::manifest::{DpiAwareness, ExecutionLevel};
use embed_manifest::{embed_manifest, new_manifest};

fn derleme_bilgisi() -> String {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let surum = std::process::Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.split_whitespace().nth(1).map(str::to_string))
        .map_or_else(|| "Rust".to_string(), |v| format!("Rust {v}"));
    let hedef = std::env::var("TARGET").unwrap_or_default();
    let profil = std::env::var("PROFILE").unwrap_or_default();
    format!("{surum} · {hedef} · {profil}")
}

fn main() {
    println!("cargo:rustc-env=JS_DERLEME={}", derleme_bilgisi());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/app.ico");
    println!("cargo:rerun-if-env-changed=JS_GUI_NO_ADMIN");
    if std::env::var_os("CARGO_CFG_WINDOWS").is_none() {
        return;
    }
    let level = if std::env::var_os("JS_GUI_NO_ADMIN").is_some() {
        ExecutionLevel::AsInvoker
    } else {
        ExecutionLevel::RequireAdministrator
    };
    embed_manifest(
        new_manifest("JournalScanner")
            .requested_execution_level(level)
            .dpi_awareness(DpiAwareness::PerMonitorV2),
    )
    .expect("manifest gömülemedi");
    let surum = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/app.ico")
        .set("FileDescription", "JournalScanner")
        .set("ProductName", "JournalScanner")
        .set("FileVersion", &surum)
        .set("ProductVersion", &surum)
        .set("OriginalFilename", "JournalScanner.exe");
    if let Err(e) = res.compile() {
        println!("cargo:warning=simge gömülemedi: {e}");
    }
}
