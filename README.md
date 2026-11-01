# JournalScanner

📖 **[Kullanım Kılavuzu](KULLANIM.md)**

Windows için Minecraft hile tarayıcısı. Dosyaların adına değil içeriğine bakar. Rust ile yazıldı, tek exe.

**İndir:** [Releases](../../releases)

## Kullanım

`JournalScanner.exe` → sağ tık → **Yönetici olarak çalıştır**. **Tüm taramaları başlat** ile hepsini, ya da her sayfadaki **Tara** düğmesiyle yalnızca o kategoriyi tarayın. Tarama yalnızca okur, hiçbir dosyayı değiştirmez.

## Derleme

[Rust](https://rustup.rs) + Visual Studio Build Tools ("C++ ile masaüstü geliştirme"):

```bat
cargo build --release -p js-gui
```

Çıktı: `target\release\JournalScanner.exe`

## Yapı

| Klasör | İçerik |
| --- | --- |
| `crates/js-core` | Tarama motorları |
| `crates/js-native` | DLL / bellek tarayıcısı |
| `crates/js-gui` | Arayüz |
| `crates/js-cli` | Komut satırı aracı |

## Emeği geçenler

- [Jestron](https://github.com/jesthub25): ana geliştirici, fikir
- [duvo](https://github.com/duvofan): Rust portu

## Lisans

[MIT](LICENSE). Programı ücretsiz kullanabilir, kendi sunucunuzda ya da topluluğunuzda dağıtabilir, kodunu değiştirip kendi sürümünüzü yapabilirsiniz. Tek şart, lisans metnini ve emeği geçenlerin adını korumaktır.
