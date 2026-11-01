use crate::analysis::*;
use crate::classfile::*;
use crate::util::*;
use std::collections::BTreeSet;

pub fn is_known_java_pkg(n: &str) -> bool {
    const PK: [&str; 51] = [
        "java/",
        "javax/",
        "jdk/",
        "sun/",
        "com/sun/",
        "org/w3c/",
        "org/xml/",
        "org/ietf/",
        "net/minecraft/",
        "com/mojang/",
        "net/minecraftforge/",
        "net/neoforged/",
        "cpw/mods/",
        "net/fabricmc/",
        "org/quiltmc/",
        "optifine/",
        "net/optifine/",
        "shadersmod/",
        "org/lwjgl/",
        "org/spongepowered/",
        "org/objectweb/asm/",
        "io/netty/",
        "com/google/",
        "org/apache/",
        "org/slf4j/",
        "org/lz4/",
        "it/unimi/",
        "com/ibm/icu/",
        "joptsimple/",
        "oshi/",
        "com/github/oshi/",
        "org/joml/",
        "org/jetbrains/",
        "kotlin/",
        "kotlinx/",
        "scala/",
        "org/yaml/",
        "com/electronwill/",
        "org/intellij/",
        "com/mojang/",
        "net/jodah/",
        "org/checkerframework/",
        "javassist/",
        "org/tukaani/",
        "com/typesafe/",
        "org/reflections/",
        "ca/weblite/",
        "org/bouncycastle/",
        "org/codehaus/",
        "com/fasterxml/",
        "org/openjdk/",
    ];
    PK.iter().any(|p| n.starts_with(p))
}

pub fn zip_local_scan(p: &[u8]) -> Option<Vec<ZipEnt>> {
    let n = p.len();
    let mut out: Vec<ZipEnt> = Vec::new();
    let mut pos = 0usize;
    while pos + 30 <= n && out.len() < 20000 {
        if rd32(p, pos) != 0x04034B50 {
            let mut k = pos + 1;
            let mut found = false;
            while k + 30 <= n {
                let window = n - k - 29;
                match memchr::memchr(b'P', &p[k..k + window]) {
                    None => break,
                    Some(i) => {
                        k += i;
                        if rd32(p, k) == 0x04034B50 {
                            found = true;
                            break;
                        }
                        k += 1;
                    }
                }
            }
            if !found {
                break;
            }
            pos = k;
            continue;
        }
        let flags = rd16(p, pos + 6);
        let method = rd16(p, pos + 8);
        let cs = rd32(p, pos + 18);
        let us = rd32(p, pos + 22);
        let nl = rd16(p, pos + 26) as usize;
        let el = rd16(p, pos + 28) as usize;
        let ds = pos + 30 + nl + el;
        if ds > n {
            break;
        }
        let name_end = (pos + 30 + nl).min(n);
        let mut e = ZipEnt {
            name: sanitize_j(&p[pos + 30..name_end], 200),
            method,
            usize_: us,
            csize: cs,
            data_off: ds,
        };
        if (flags & 8) != 0 || (cs == 0 && method == 8) {
            let mut t2 = Vec::new();
            let used = if method == 8 {
                inflate_raw(&p[ds..], &mut t2, 4 << 20)
            } else {
                None
            };
            let Some(used) = used else {
                pos = ds;
                continue;
            };
            e.csize = used as u32;
            out.push(e);
            pos = ds + used;
            if (flags & 8) != 0 && pos + 4 <= n && rd32(p, pos) == 0x08074B50 {
                pos += 16;
            } else if (flags & 8) != 0 {
                pos += 12;
            }
            continue;
        }
        if ds as u64 + cs as u64 > n as u64 {
            break;
        }
        pos = ds + cs as usize;
        out.push(e);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub fn is_meta_name(low: &str) -> bool {
    const NM: [&str; 9] = [
        "fabric.mod.json",
        "quilt.mod.json",
        "meta-inf/mods.toml",
        "meta-inf/neoforge.mods.toml",
        "mcmod.info",
        "plugin.yml",
        "paper-plugin.yml",
        "bungee.yml",
        "meta-inf/manifest.mf",
    ];
    NM.contains(&low)
}

pub fn is_text_res_name(low: &str) -> bool {
    const EX: [&str; 9] = [
        ".json",
        ".toml",
        ".mf",
        ".yml",
        ".yaml",
        ".info",
        ".properties",
        ".cfg",
        ".txt",
    ];
    EX.iter().any(|x| low.ends_with(x))
}

pub type ScanBuf<'a> = &'a mut dyn FnMut(&mut Analysis, &[u8], bool);

struct PayState {
    total: usize,
    tmp: Vec<u8>,
    text_files: i32,
    seen: BTreeSet<String>,
}

const DEEP_CAP: usize = 40000;
const TOTAL_CAP: usize = 160 << 20;

fn deep_count(a: &Analysis) -> usize {
    a.jacc.cls.len() + a.jacc.van.len()
}

fn do_entries(d: &[u8], ents: &[ZipEnt], a: &mut Analysis, scan_buf: ScanBuf, depth: i32, st: &mut PayState) {
    for e in ents {
        if a.zip_names.len() < 500 {
            a.zip_names.push(e.name.clone());
        }
    }
    let mut has_meta = false;
    let mut third_entries = 0usize;
    let mut mc_entries = 0usize;
    for e in ents {
        let low = lower_str(&e.name);
        if is_meta_name(&low) {
            has_meta = true;
        }
        if low.ends_with(".class") {
            if low.starts_with("net/minecraft/") {
                mc_entries += 1;
            }
            if !is_known_java_pkg(&e.name) {
                third_entries += 1;
            }
        }
    }
    let skip_classes = !has_meta && (third_entries == 0 || mc_entries >= 1500);
    if skip_classes {
        a.jacc.lib_only = true;
    }
    for e in ents {
        if deep_count(a) >= DEEP_CAP || st.total > TOTAL_CAP {
            break;
        }
        let low = lower_str(&e.name);
        if low.ends_with(".class") {
            if skip_classes || e.usize_ > (4 << 20) {
                continue;
            }
            if !zip_extract(d, e, &mut st.tmp, 4 << 20) {
                continue;
            }
            st.total += st.tmp.len();
            let ci = parse_class(&st.tmp);
            let nm = match &ci {
                Some(c) => c.name.clone(),
                None => e.name.clone(),
            };
            if st.seen.contains(&nm) {
                continue;
            }
            st.seen.insert(nm);
            if crate::jbytecode::java_add_class(&mut a.jacc, &st.tmp) == 2 {
                continue;
            }
            if let Some(c) = ci {
                if a.classes.len() < 600 {
                    a.classes.push(c);
                }
            }
            scan_buf(a, &st.tmp, true);
        } else if low.ends_with(".jar") && depth < 2 && e.usize_ <= (96 << 20) && (e.method == 0 || e.method == 8) {
            let mut inner = Vec::new();
            if !zip_extract(d, e, &mut inner, 96 << 20) || inner.len() < 30 {
                continue;
            }
            st.total += inner.len();
            scan_payload(&inner, a, &mut *scan_buf, depth + 1);
        } else if e.usize_ <= (512 << 10) && (is_meta_name(&low) || (is_text_res_name(&low) && st.text_files < 300)) {
            if !zip_extract(d, e, &mut st.tmp, 512 << 10) {
                continue;
            }
            st.total += st.tmp.len();
            if !is_meta_name(&low) {
                st.text_files += 1;
            }
            scan_buf(a, &st.tmp, true);
            if depth == 0 && is_meta_name(&low) && !a.jmeta.contains_key(&low) {
                let keep = st.tmp.len().min(24576);
                a.jmeta.insert(low, st.tmp[..keep].to_vec());
            }
        }
    }
}

pub fn scan_payload(d: &[u8], a: &mut Analysis, scan_buf: ScanBuf, depth: i32) {
    let n = d.len();
    let mut zips: BTreeSet<usize> = BTreeSet::new();
    let mut st = PayState {
        total: 0,
        tmp: Vec::new(),
        text_files: 0,
        seen: BTreeSet::new(),
    };
    let mut i = 0usize;
    while i + 22 <= n && zips.len() < 8 {
        let window = n - i - 21;
        let Some(off) = memchr::memchr(b'P', &d[i..i + window]) else {
            break;
        };
        i += off;
        if d[i + 1] == b'K' && d[i + 2] == 5 && d[i + 3] == 6 {
            if let Some((ents, zs)) = zip_list_at(d, i) {
                if !zips.contains(&zs) {
                    zips.insert(zs);
                    a.zip_count += 1;
                    do_entries(d, &ents, a, &mut *scan_buf, depth, &mut st);
                }
            }
        }
        i += 1;
    }
    if zips.is_empty() && n >= 64 && rd32(d, 0) == 0x04034B50 {
        if let Some(ents) = zip_local_scan(d) {
            a.zip_count += 1;
            do_entries(d, &ents, a, &mut *scan_buf, depth, &mut st);
            a.zip_names
                .push("(merkez dizini bozuk/yok: yerel başlıklardan okundu)".to_string());
        }
    }
    let mut i = 0usize;
    while i + 32 <= n && deep_count(a) < DEEP_CAP {
        let window = n - i - 31;
        let Some(off) = memchr::memchr(0xCA, &d[i..i + window]) else {
            break;
        };
        i += off;
        if d[i + 1] == 0xFE && d[i + 2] == 0xBA && d[i + 3] == 0xBE {
            if let Some(ci) = parse_class(&d[i..]) {
                let l = ci.length;
                if !st.seen.contains(&ci.name) {
                    st.seen.insert(ci.name.clone());
                    if crate::jbytecode::java_add_class(&mut a.jacc, &d[i..i + l]) != 2 {
                        if a.classes.len() < 600 {
                            a.classes.push(ci);
                        }
                        scan_buf(a, &d[i..i + l], true);
                    }
                }
                i += l;
                continue;
            }
        }
        i += 1;
    }
}

#[derive(Debug, Clone, Default)]
pub struct UnloadEnt {
    pub base: u64,
    pub size: u64,
    pub seq: u32,
    pub ts: u32,
    pub checksum: u32,
    pub name: String,
}

pub fn parse_unload_trace(b: &[u8], elem_size: usize, count: usize) -> Option<Vec<UnloadEnt>> {
    let mut out: Vec<UnloadEnt> = Vec::new();
    if !(92..=256).contains(&elem_size) || count == 0 || count > 1024 {
        return None;
    }
    for i in 0..count {
        let e = i * elem_size;
        if e + elem_size > b.len() {
            break;
        }
        let mut u = UnloadEnt {
            base: rd64(b, e),
            size: rd64(b, e + 8),
            seq: rd32(b, e + 16),
            ts: rd32(b, e + 20),
            checksum: rd32(b, e + 24),
            name: String::new(),
        };
        for k in 0..32 {
            let ch = rd16(b, e + 28 + k * 2);
            if ch == 0 {
                break;
            }
            u.name.push(if (0x20..0x7F).contains(&ch) {
                ch as u8 as char
            } else {
                '?'
            });
        }
        if u.name.is_empty() || u.base == 0 {
            continue;
        }
        if u.size == 0 || u.size > (1u64 << 30) {
            continue;
        }
        if (u.base & 0xFFF) != 0 || (u.size & 0xFFF) != 0 || u.name.len() < 5 {
            continue;
        }
        {
            let ok_name = u.name.bytes().all(|c| {
                is_alnum(c) || matches!(c, b'.' | b'_' | b'-' | b'+' | b' ' | b'(' | b')' | b'$' | b'@' | b'~')
            });
            if !ok_name {
                continue;
            }
            if u.name.len() < 31 {
                match u.name.rfind('.') {
                    None => continue,
                    Some(dp) => {
                        let l = u.name.len() - dp;
                        if !(3..=5).contains(&l) {
                            continue;
                        }
                    }
                }
            }
        }
        out.push(u);
    }
    out.sort_by(|a, c| c.seq.cmp(&a.seq));
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_pkg() {
        assert!(is_known_java_pkg("java/lang/String"));
        assert!(!is_known_java_pkg("a/b/C"));
    }
    #[test]
    fn local_scan_stored() {
        let mut z = vec![0x50, 0x4B, 3, 4, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        z.extend_from_slice(&0u32.to_le_bytes()); // crc
        z.extend_from_slice(&2u32.to_le_bytes()); // csize
        z.extend_from_slice(&2u32.to_le_bytes()); // usize
        z.extend_from_slice(&1u16.to_le_bytes()); // name len
        z.extend_from_slice(&0u16.to_le_bytes());
        z.push(b'a');
        z.extend_from_slice(b"hi");
        let e = zip_local_scan(&z).unwrap();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].name, "a");
        let mut o = Vec::new();
        assert!(zip_extract(&z, &e[0], &mut o, 100));
        assert_eq!(o, b"hi");
    }
    #[test]
    fn unload_rejects_garbage() {
        assert!(parse_unload_trace(&[0u8; 10], 10, 1).is_none());
        let v = parse_unload_trace(&[0u8; 200], 100, 2).unwrap();
        assert!(v.is_empty());
    }
}
