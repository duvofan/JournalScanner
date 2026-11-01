use crate::util::*;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default)]
pub struct PeSec {
    pub name: String,
    pub vsize: u32,
    pub rva: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub chars: u32,
    pub ent: f64,
}

#[derive(Debug, Clone, Default)]
pub struct PeImp {
    pub dll: String,
    pub func: String,
    pub slot_rva: u32,
    pub slot_va: u64,
    pub delay: bool,
}

#[derive(Debug, Clone, Default)]
pub struct PeInfo {
    pub valid: bool,
    pub is64: bool,
    pub is_dll: bool,
    pub mem_layout: bool,
    pub has_cert: bool,
    pub machine: u16,
    pub nsec: u16,
    pub subsystem: u16,
    pub dll_chars: u16,
    pub timestamp: u32,
    pub size_of_image: u32,
    pub entry_rva: u32,
    pub size_of_headers: u32,
    pub cert_off: u32,
    pub cert_size: u32,
    pub checksum: u32,
    pub image_base: u64,
    pub secs: Vec<PeSec>,
    pub imps: Vec<PeImp>,
    pub exps: Vec<String>,
    pub pdb: String,
    pub imp_dlls: BTreeSet<String>,
    pub imp_funcs: BTreeSet<String>,
    pub exp_total: u32,
    pub exp_jvm: u32,
    pub exp_jdk: u32,
    pub exp_cef: u32,
    pub exp_create: bool,
    pub exp_dir_rva: u32,
    pub exp_dir_size: u32,
}

pub fn read_cstr(p: &[u8], off: usize, max_len: usize) -> String {
    let mut v = Vec::new();
    let mut o = off;
    while o < p.len() && v.len() < max_len && p[o] != 0 {
        v.push(p[o]);
        o += 1;
    }
    String::from_utf8_lossy(&v).into_owned()
}

const NONE: usize = usize::MAX;

pub fn parse_pe(p: &[u8], mem_layout: bool) -> Option<PeInfo> {
    let n = p.len();
    let mut o = PeInfo::default();
    if n < 0x200 || p[0] != b'M' || p[1] != b'Z' {
        return None;
    }
    let lf = rd32(p, 0x3C);
    if lf < 0x40 || lf as usize + 0x108 > n {
        return None;
    }
    let lf = lf as usize;
    if rd32(p, lf) != 0x0000_4550 {
        return None;
    }
    let fh = lf + 4;
    o.machine = rd16(p, fh);
    o.nsec = rd16(p, fh + 2);
    o.timestamp = rd32(p, fh + 4);
    let sz_opt = rd16(p, fh + 16) as usize;
    let chars = rd16(p, fh + 18);
    o.is_dll = chars & 0x2000 != 0;
    if o.machine != 0x8664 && o.machine != 0x014C && o.machine != 0xAA64 {
        return None;
    }
    if o.nsec == 0 || o.nsec > 96 {
        return None;
    }
    let oh = fh + 20;
    let oh_off = lf + 24;
    if sz_opt < 96 || oh_off + sz_opt > n {
        return None;
    }
    let magic = rd16(p, oh);
    o.checksum = rd32(p, oh + 64);
    let dirs;
    let mut num_dirs;
    if magic == 0x20B {
        o.is64 = true;
        if sz_opt < 112 {
            return None;
        }
        o.entry_rva = rd32(p, oh + 16);
        o.image_base = rd64(p, oh + 24);
        o.size_of_image = rd32(p, oh + 56);
        o.size_of_headers = rd32(p, oh + 60);
        o.subsystem = rd16(p, oh + 68);
        o.dll_chars = rd16(p, oh + 70);
        num_dirs = rd32(p, oh + 108);
        dirs = oh + 112;
    } else if magic == 0x10B {
        o.is64 = false;
        o.entry_rva = rd32(p, oh + 16);
        o.image_base = rd32(p, oh + 28) as u64;
        o.size_of_image = rd32(p, oh + 56);
        o.size_of_headers = rd32(p, oh + 60);
        o.subsystem = rd16(p, oh + 68);
        o.dll_chars = rd16(p, oh + 70);
        num_dirs = rd32(p, oh + 92);
        dirs = oh + 96;
    } else {
        return None;
    }
    if num_dirs > 16 {
        num_dirs = 16;
    }
    let dirs_avail = (oh + sz_opt).saturating_sub(dirs);
    if num_dirs as usize * 8 > dirs_avail {
        num_dirs = (dirs_avail / 8) as u32;
    }
    let sec_off = oh_off + sz_opt;
    if sec_off + o.nsec as usize * 40 > n {
        return None;
    }
    o.mem_layout = mem_layout;
    for i in 0..o.nsec as usize {
        let s = sec_off + i * 40;
        let mut ps = PeSec::default();
        let mut nm = String::new();
        for k in 0..8 {
            let c = p[s + k];
            if c == 0 {
                break;
            }
            nm.push(if !(0x20..=0x7E).contains(&c) { '?' } else { c as char });
        }
        ps.name = nm;
        ps.vsize = rd32(p, s + 8);
        ps.rva = rd32(p, s + 12);
        ps.raw_size = rd32(p, s + 16);
        ps.raw_ptr = rd32(p, s + 20);
        ps.chars = rd32(p, s + 36);
        if !mem_layout && ps.raw_size != 0 && ps.raw_ptr as u64 + ps.raw_size as u64 <= n as u64 {
            ps.ent = entropy_of(&p[ps.raw_ptr as usize..(ps.raw_ptr as usize + ps.raw_size as usize)]);
        } else if mem_layout && ps.vsize != 0 && ps.rva as u64 + ps.vsize as u64 <= n as u64 {
            ps.ent = entropy_of(&p[ps.rva as usize..(ps.rva as usize + ps.vsize as usize)]);
        }
        o.secs.push(ps);
    }
    let rva2off = |o: &PeInfo, rva: u32, need: usize| -> usize {
        if mem_layout {
            return if rva as u64 + need as u64 <= n as u64 {
                rva as usize
            } else {
                NONE
            };
        }
        if rva < o.size_of_headers {
            return if rva as u64 + need as u64 <= n as u64 {
                rva as usize
            } else {
                NONE
            };
        }
        for s in &o.secs {
            let span = s.vsize.max(s.raw_size);
            if rva >= s.rva && rva - s.rva < span {
                let d = rva - s.rva;
                if d >= s.raw_size {
                    return NONE;
                }
                let off = s.raw_ptr as u64 + d as u64;
                return if off + need as u64 <= n as u64 {
                    off as usize
                } else {
                    NONE
                };
            }
        }
        NONE
    };
    let dir_rva = |i: u32| -> u32 {
        if i < num_dirs {
            rd32(p, dirs + i as usize * 8)
        } else {
            0
        }
    };
    let dir_size = |i: u32| -> u32 {
        if i < num_dirs {
            rd32(p, dirs + i as usize * 8 + 4)
        } else {
            0
        }
    };
    let psz: usize = if o.is64 { 8 } else { 4 };
    let parse_thunks = |o: &mut PeInfo, dll: &str, int_rva: u32, iat_rva: u32, delay: bool| {
        for j in 0..4096u32 {
            let to = rva2off(o, int_rva.wrapping_add((j as usize * psz) as u32), psz);
            if to == NONE {
                break;
            }
            let val: u64 = if psz == 8 { rd64(p, to) } else { rd32(p, to) as u64 };
            if val == 0 {
                break;
            }
            let slot_rva = iat_rva.wrapping_add((j as usize * psz) as u32);
            let mut im = PeImp {
                dll: dll.to_string(),
                func: String::new(),
                delay,
                slot_rva,
                slot_va: o.image_base.wrapping_add(slot_rva as u64),
            };
            let ord = (val >> (psz * 8 - 1)) & 1 != 0;
            if ord {
                im.func = format!("#{}", (val & 0xFFFF) as u32);
            } else {
                let no = rva2off(o, val as u32, 3);
                if no == NONE {
                    break;
                }
                im.func = read_cstr(p, no + 2, 128);
            }
            o.imp_funcs.insert(lower_str(&im.func));
            o.imps.push(im);
        }
    };
    let ir = dir_rva(1);
    if ir != 0 {
        for i in 0..1024u32 {
            let d = rva2off(&o, ir.wrapping_add(i * 20), 20);
            if d == NONE {
                break;
            }
            let oft = rd32(p, d);
            let name_rva = rd32(p, d + 12);
            let ft = rd32(p, d + 16);
            if oft == 0 && name_rva == 0 && ft == 0 {
                break;
            }
            let no = rva2off(&o, name_rva, 2);
            if no == NONE {
                continue;
            }
            let dll = read_cstr(p, no, 128);
            o.imp_dlls.insert(lower_str(&dll));
            parse_thunks(&mut o, &dll, if oft != 0 { oft } else { ft }, ft, false);
        }
    }
    let dr = dir_rva(13);
    if dr != 0 {
        for i in 0..256u32 {
            let d = rva2off(&o, dr.wrapping_add(i * 32), 32);
            if d == NONE {
                break;
            }
            let attr = rd32(p, d);
            let mut name_rva = rd32(p, d + 4);
            let mut iat = rd32(p, d + 12);
            let mut intr = rd32(p, d + 16);
            if name_rva == 0 {
                break;
            }
            if attr & 1 == 0 {
                if (name_rva as u64) < o.image_base {
                    break;
                }
                name_rva = (name_rva as u64).wrapping_sub(o.image_base) as u32;
                iat = (iat as u64).wrapping_sub(o.image_base) as u32;
                intr = (intr as u64).wrapping_sub(o.image_base) as u32;
            }
            let no = rva2off(&o, name_rva, 2);
            if no == NONE {
                continue;
            }
            let dll = read_cstr(p, no, 128);
            o.imp_dlls.insert(lower_str(&dll));
            parse_thunks(&mut o, &dll, intr, iat, true);
        }
    }
    let er = dir_rva(0);
    if er != 0 {
        o.exp_dir_rva = er;
        o.exp_dir_size = dir_size(0);
        let e = rva2off(&o, er, 40);
        if e != NONE {
            let mut n_names = rd32(p, e + 24);
            let names_rva = rd32(p, e + 32);
            if n_names > 100000 {
                n_names = 100000;
            }
            for i in 0..n_names {
                let a = rva2off(&o, names_rva.wrapping_add(i * 4), 4);
                if a == NONE {
                    break;
                }
                let sidx = rva2off(&o, rd32(p, a), 2);
                if sidx == NONE {
                    continue;
                }
                let nm = read_cstr(p, sidx, 128);
                o.exp_total += 1;
                if nm == "JNI_CreateJavaVM" {
                    o.exp_create = true;
                }
                if nm.starts_with("JVM_") {
                    o.exp_jvm += 1;
                }
                if nm.starts_with("Java_java_")
                    || nm.starts_with("Java_sun_")
                    || nm.starts_with("Java_jdk_")
                    || nm.starts_with("Java_com_sun_")
                {
                    o.exp_jdk += 1;
                }
                if nm.starts_with("cef_") {
                    o.exp_cef += 1; // Chromium Embedded Framework (CEF/MCEF) export imzası
                }
                if o.exps.len() < 20000 {
                    o.exps.push(nm);
                }
            }
        }
    }
    let dbr = dir_rva(6);
    if dbr != 0 {
        let dsz = dir_size(6);
        let mut cnt = dsz / 28;
        if cnt > 16 {
            cnt = 16;
        }
        for i in 0..cnt {
            let d = rva2off(&o, dbr.wrapping_add(i * 28), 28);
            if d == NONE {
                break;
            }
            if rd32(p, d + 12) != 2 {
                continue;
            }
            let sz = rd32(p, d + 16);
            let addr = rd32(p, d + 20);
            let raw = rd32(p, d + 24);
            let off = if mem_layout {
                rva2off(&o, addr, 24)
            } else {
                raw as usize
            };
            if off == NONE || sz < 25 || off as u64 + 24 > n as u64 {
                continue;
            }
            if p.get(off..off + 4) == Some(b"RSDS") {
                o.pdb = read_cstr(p, off + 24, 260);
                break;
            }
        }
    }
    if !mem_layout {
        o.cert_off = dir_rva(4);
        o.cert_size = dir_size(4);
        o.has_cert = o.cert_size > 8 && o.cert_off as u64 + o.cert_size as u64 <= n as u64 + 0x10000;
    }
    o.valid = true;
    Some(o)
}

pub fn pe_rva_to_off(pe: &PeInfo, n: usize, rva: u32) -> usize {
    if pe.mem_layout {
        return if (rva as usize) < n { rva as usize } else { NONE };
    }
    for s in &pe.secs {
        let span = s.vsize.max(s.raw_size);
        if rva >= s.rva && rva - s.rva < span {
            let d = rva - s.rva;
            if d >= s.raw_size {
                return NONE;
            }
            let off = s.raw_ptr as u64 + d as u64;
            return if off < n as u64 { off as usize } else { NONE };
        }
    }
    NONE
}

pub const NO_OFF: usize = NONE;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_garbage() {
        assert!(parse_pe(&[0u8; 100], false).is_none());
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        assert!(parse_pe(&b, false).is_none());
    }
}
