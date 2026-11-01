use crate::events::*;
use crate::rx::*;
use crate::util::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Devices::DeviceAndDriverInstallation::*;
use windows::Win32::Devices::Properties::DEVPROPTYPE;
use windows::Win32::Foundation::{GetLastError, DEVPROPKEY, ERROR_SUCCESS, HWND};
use windows::Win32::System::Registry::*;

pub type OptT = Option<f64>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PropKind {
    #[default]
    None,
    Str,
    List,
    Time,
    Bool,
    U32,
    Guid,
}

#[derive(Debug, Clone, Default)]
pub struct PropVal {
    pub k: PropKind,
    pub s: String,
    pub list: StrList,
    pub t: OptT,
    pub b: bool,
    pub u: u32,
}

#[derive(Debug, Clone, Default)]
pub struct DevRec {
    pub id: String,
    pub props: BTreeMap<String, PropVal>,
}
impl DevRec {
    pub fn get(&self, k: &str) -> Option<&PropVal> {
        self.props.get(k)
    }
    pub fn str(&self, k: &str) -> String {
        match self.get(k) {
            Some(p) if p.k == PropKind::Str => p.s.clone(),
            _ => String::new(),
        }
    }
    pub fn time(&self, k: &str) -> OptT {
        match self.get(k) {
            Some(p) if p.k == PropKind::Time => p.t,
            _ => None,
        }
    }
    pub fn is_true(&self, k: &str) -> bool {
        matches!(self.get(k), Some(p) if p.k == PropKind::Bool && p.b)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DevEvent {
    pub time: f64,
    pub id: i32,
    pub data: Vec<(String, String)>,
}
impl DevEvent {
    pub fn get(&self, k: &str) -> String {
        self.data
            .iter()
            .find(|kv| kv.0 == k)
            .map(|kv| kv.1.clone())
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct StoragePart {
    pub time: f64,
    pub model: String,
    pub serial: String,
    pub capacity: String,
}

#[derive(Debug, Clone, Default)]
pub struct UsbDev {
    pub name: String,
    pub id: String,
    pub vid: String,
    pub pid: String,
    pub serial: String,
    pub manufacturer: String,
    pub state: String,
    pub functions: StrList,
    pub source: StrList,
    pub present: bool,
    pub new_in_period: bool,
    pub first_install: OptT,
    pub last_arrival: OptT,
    pub last_removal: OptT,
    pub events: Vec<f64>,
    pub storage: Vec<StoragePart>,
}

#[derive(Debug, Clone, Default)]
pub struct BtDev {
    pub name: String,
    pub mac: String,
    pub r#type: String,
    pub category: String,
    pub last_connected_source: String,
    pub last_connected: OptT,
    pub first_install: OptT,
    pub services: StrList,
    pub file_transfer_services: StrList,
    pub source: StrList,
    pub new_in_period: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BtRun {
    pub time: f64,
    pub path: String,
    pub source: String,
}
#[derive(Debug, Clone, Default)]
pub struct BtFile {
    pub path: String,
    pub time: f64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct DeviceResult {
    pub days: i32,
    pub cutoff: f64,
    pub now: f64,
    pub bluetooth: Vec<BtDev>,
    pub bt_older: i32,
    pub bt_file_runs: Vec<BtRun>,
    pub bt_files: Vec<BtFile>,
    pub usb: Vec<UsbDev>,
    pub usb_internal_hidden: i32,
    pub notes: StrList,
    pub errors: StrList,
    pub supported: bool,
}
impl Default for DeviceResult {
    fn default() -> Self {
        DeviceResult {
            days: 5,
            cutoff: 0.0,
            now: 0.0,
            bluetooth: Vec::new(),
            bt_older: 0,
            bt_file_runs: Vec::new(),
            bt_files: Vec::new(),
            usb: Vec::new(),
            usb_internal_hidden: 0,
            notes: Vec::new(),
            errors: Vec::new(),
            supported: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BtReg {
    pub name: String,
    pub cod: Option<u32>,
    pub last_connected: OptT,
    pub last_seen: OptT,
}

fn ft_dt(ft: u64, now: f64) -> OptT {
    let t = filetime_to_epoch(ft)?;
    let year: i32 = fmt_local(t, "%Y").trim().parse().ok()?;
    if year < 2000 || t > now + 2.0 * 86400.0 {
        return None;
    }
    Some(t)
}

fn class_tr(c: &str) -> Option<&'static str> {
    Some(match c {
        "diskdrive" => "Depolama (USB bellek / harici disk)",
        "wpd" => "Taşınabilir cihaz (telefon / tablet - dosya erişimi)",
        "keyboard" => "Klavye",
        "mouse" => "Fare",
        "hidclass" => "Giriş aygıtı (HID)",
        "image" => "Kamera / tarayıcı",
        "camera" => "Kamera",
        "media" => "Ses aygıtı",
        "audioendpoint" => "Ses (hoparlör / mikrofon)",
        "net" => "Ağ adaptörü",
        "bluetooth" => "Bluetooth adaptörü",
        "printer" => "Yazıcı",
        "ports" => "Seri port (COM)",
        "modem" => "Modem",
        "cdrom" => "CD/DVD sürücü",
        "smartcardreader" => "Akıllı kart okuyucu",
        "biometric" => "Parmak izi okuyucu",
        "xboxcomposite" => "Oyun kumandası",
        "xnacomposite" => "Oyun kumandası",
        "volume" => "Disk bölümü (birim)",
        "usb" => "USB hub / bileşik aygıt",
        "usbdevice" => "USB aygıt",
        "androidusbdeviceclass" => "Android (ADB) arabirimi",
        "apple mobile device usb driver" => "Apple mobil aygıt",
        "sensor" => "Sensor",
        "firmware" => "Aygıt yazılımı",
        "softwarecomponent" => "Yazılım bileşeni",
        "extension" => "Sürücü uzantısı",
        _ => return None,
    })
}

fn func_of(cls: &str) -> String {
    let c = py_lower(&pystrip(cls));
    if c.is_empty()
        || c == "softwarecomponent"
        || c == "extension"
        || c == "firmware"
        || c == "volumesnapshot"
        || c == "system"
    {
        return String::new();
    }
    match class_tr(&c) {
        Some(v) => v.to_string(),
        None => cls.to_string(),
    }
}

fn cod_major(k: i32) -> Option<&'static str> {
    Some(match k {
        1 => "Bilgisayar",
        2 => "Telefon",
        3 => "Ağ erişim noktası",
        4 => "Ses / görüntü (kulaklık, hoparlör)",
        5 => "Çevre birimi (klavye / fare / kumanda)",
        6 => "Görüntüleme (yazıcı / kamera)",
        7 => "Giyilebilir (saat)",
        8 => "Oyuncak",
        9 => "Sağlık aygıtı",
        _ => return None,
    })
}

fn bt_service(k: &str) -> Option<&'static str> {
    Some(match k {
        "00001105" => "OBEX Nesne Gönderme (dosya aktarımı)",
        "00001106" => "OBEX Dosya Aktarımı",
        "0000111e" => "Eller serbest (Hands-Free)",
        "0000110b" => "Ses alıcı (A2DP)",
        "0000110a" => "Ses kaynağı (A2DP)",
        "00001124" => "Giriş aygıtı (HID)",
        "00001101" => "Seri port (SPP)",
        "00001116" => "Ağ erişimi (NAP)",
        "00001115" => "Kişisel ağ (PANU)",
        "0000112f" => "Rehber erişimi (PBAP)",
        "00001132" => "Mesaj erişimi (MAP)",
        "00001108" => "Kulaklık (Headset)",
        "0000110e" => "Uzaktan kumanda (AVRCP)",
        "00001200" => "PnP bilgisi",
        _ => return None,
    })
}

fn rx_vidpid() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx::new("VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", 0))
}
fn rx_btmac() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx::new("DEV_([0-9A-Fa-f]{12})", Rx::I))
}
fn rx_gm() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx::new(r"BTHENUM\\\{([0-9A-F]{8})-", 0))
}
fn rx_macr() -> &'static Rx {
    static R: OnceLock<Rx> = OnceLock::new();
    R.get_or_init(|| Rx::new(r"[&_]([0-9A-F]{12})(?:_|$)", 0))
}

fn mac_fmt(m: &str) -> String {
    let u = upper_ascii(m);
    if u.len() != 12 {
        return u;
    }
    let p: StrList = (0..12)
        .step_by(2)
        .map(|i| u.get(i..i + 2).unwrap_or("").to_string())
        .collect();
    join(&p, ":")
}

fn is_top_usb(r: &DevRec) -> bool {
    let iid = py_upper(&r.id);
    if !starts(&iid, "USB\\") {
        return false;
    }
    if has(&iid, "ROOT_HUB") || has(&iid, "&MI_") {
        return false;
    }
    rx_vidpid().search(iid.as_bytes(), 0).is_some()
}

pub fn build_usb(
    devices: &[DevRec],
    present_ids: &BTreeSet<String>,
    events: &[DevEvent],
    part_events: &[DevEvent],
    cutoff: f64,
    hidden_internal: &mut i32,
) -> Vec<UsbDev> {
    let mut children: BTreeMap<String, Vec<&DevRec>> = BTreeMap::new();
    for d in devices {
        let p = py_upper(&d.str("Parent"));
        if !p.is_empty() {
            children.entry(p).or_default().push(d);
        }
    }
    let mut ev_by: BTreeMap<String, Vec<&DevEvent>> = BTreeMap::new();
    let mut part_by: BTreeMap<String, Vec<&DevEvent>> = BTreeMap::new();
    for e in events {
        let mut iid = e.get("DeviceInstanceId");
        if iid.is_empty() {
            iid = e.get("DeviceInstanceID");
        }
        let iid = py_upper(&iid);
        if !iid.is_empty() {
            ev_by.entry(iid).or_default().push(e);
        }
    }
    for e in part_events {
        let pid = py_upper(&e.get("ParentId"));
        if !pid.is_empty() {
            part_by.entry(pid).or_default().push(e);
        }
    }
    let mut out: Vec<UsbDev> = Vec::new();
    *hidden_internal = 0;
    let usb_func = class_tr("usb").unwrap_or_default();
    for d in devices {
        if !is_top_usb(d) {
            continue;
        }
        let iid = py_upper(&d.id);
        if d.is_true("InLocalMachineContainer") {
            *hidden_internal += 1;
            continue;
        }
        let mut funcs: StrList = Vec::new();
        let mut names: StrList = Vec::new();
        let mut stack: Vec<(String, i32)> = vec![(iid.clone(), 0)];
        let mut seen: BTreeSet<String> = BTreeSet::new();
        while let Some(cur) = stack.pop() {
            if seen.contains(&cur.0) || cur.1 > 4 {
                continue;
            }
            seen.insert(cur.0.clone());
            let Some(kids) = children.get(&cur.0) else { continue };
            for ch in kids {
                let cid = py_upper(&ch.id);
                let f = func_of(&ch.str("Class"));
                if !f.is_empty() && !funcs.contains(&f) && f != usb_func {
                    funcs.push(f);
                }
                let cl = py_lower(&ch.str("Class"));
                if (cl == "diskdrive" || cl == "wpd") && !ch.str("FriendlyName").is_empty() {
                    names.push(ch.str("FriendlyName"));
                }
                stack.push((cid, cur.1 + 1));
            }
        }
        let own = func_of(&d.str("Class"));
        if funcs.is_empty() && !own.is_empty() {
            funcs.push(own);
        }
        let brdd = d.str("BusReportedDeviceDesc");
        let mut name = if !names.is_empty() {
            names[0].clone()
        } else if !d.str("FriendlyName").is_empty() {
            d.str("FriendlyName")
        } else if !brdd.is_empty() {
            brdd.clone()
        } else if !d.str("DeviceDesc").is_empty() {
            d.str("DeviceDesc")
        } else {
            iid.clone()
        };
        if !brdd.is_empty() && !has(&name, &brdd) && names.is_empty() {
            name = format!("{} ({})", name, brdd);
        }
        let m = rx_vidpid().search(iid.as_bytes(), 0);
        let mut serial = String::new();
        if iid.matches('\\').count() >= 2 {
            serial = rpartition_tail(&iid, "\\");
        }
        if has(&serial, "&") {
            serial.clear();
        }
        let present = present_ids.contains(&iid) || d.is_true("IsPresent");
        let mut evs: Vec<f64> = Vec::new();
        for sid in &seen {
            if let Some(v) = ev_by.get(sid) {
                for e in v {
                    evs.push(e.time);
                }
            }
        }
        evs.sort_by(|a, b| a.total_cmp(b));
        evs.dedup();
        let mut parts: Vec<StoragePart> = Vec::new();
        for sid in &seen {
            let Some(v) = part_by.get(sid) else { continue };
            for e in v {
                let cap = e.get("Capacity");
                let mut capf = String::new();
                if !cap.is_empty() && is_digits(&cap) {
                    let c: f64 = cap.parse().unwrap_or(0.0);
                    if c > 0.0 {
                        capf = format!("{:.1} GB", c / 1e9);
                    }
                }
                parts.push(StoragePart {
                    time: e.time,
                    model: pystrip(&format!("{} {}", e.get("Manufacturer"), e.get("Model"))),
                    serial: e.get("SerialNumber"),
                    capacity: capf,
                });
            }
        }
        let mut first = d.time("FirstInstallDate");
        if first.is_none() {
            first = d.time("InstallDate");
        }
        let arr = d.time("LastArrivalDate");
        let rem = d.time("LastRemovalDate");
        let mut recent = false;
        for x in [first, arr, rem].into_iter().flatten() {
            if x >= cutoff {
                recent = true;
            }
        }
        for t in &evs {
            if *t >= cutoff {
                recent = true;
            }
        }
        for p in &parts {
            if p.time >= cutoff {
                recent = true;
            }
        }
        if !present && !recent {
            continue;
        }
        let mut u = UsbDev::default();
        if present {
            u.state = "ŞU AN TAKILI".to_string();
        } else if matches!((rem, arr), (Some(r), Some(a)) if r >= a) {
            u.state = format!("Çıkarılmış ({})", fmt_dt(rem));
        } else {
            u.state = "Takılı değil".to_string();
        }
        u.source.push("Aygıt Yöneticisi (SetupAPI)".to_string());
        if !evs.is_empty() {
            u.source.push("Olay günlüğü: Kernel-PnP/Configuration".to_string());
        }
        if !parts.is_empty() {
            u.source.push("Olay günlüğü: Partition/Diagnostic".to_string());
        }
        u.name = name;
        u.id = d.id.clone();
        u.vid = m.as_ref().map(|m| upper_ascii(&m.group(1))).unwrap_or_default();
        u.pid = m.as_ref().map(|m| upper_ascii(&m.group(2))).unwrap_or_default();
        u.serial = serial;
        u.manufacturer = d.str("Manufacturer");
        u.functions = if funcs.is_empty() {
            vec!["USB aygıt".to_string()]
        } else {
            funcs
        };
        u.present = present;
        u.first_install = first;
        u.last_arrival = arr;
        u.last_removal = rem;
        for t in &evs {
            if *t >= cutoff {
                u.events.push(*t);
            }
        }
        parts.sort_by(|a, b| a.time.partial_cmp(&b.time).unwrap_or(std::cmp::Ordering::Equal));
        u.storage = parts;
        u.new_in_period = matches!(first, Some(f) if f >= cutoff);
        out.push(u);
    }
    let key = |x: &UsbDev| -> f64 {
        let mut mx = -1e300_f64;
        let mut any = false;
        for t in [x.last_arrival, x.last_removal].into_iter().flatten() {
            mx = mx.max(t);
            any = true;
        }
        for t in &x.events {
            mx = mx.max(*t);
            any = true;
        }
        if !any {
            mx = 86400.0; // 1970-01-02
        }
        mx
    };
    out.sort_by(|a, b| {
        if a.present != b.present {
            return if a.present {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            };
        }
        key(b).partial_cmp(&key(a)).unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

pub fn build_bluetooth(devices: &[DevRec], reg: &BTreeMap<String, BtReg>, cutoff: f64, older: &mut i32) -> Vec<BtDev> {
    struct Node<'a> {
        mac: String,
        kinds: BTreeSet<String>,
        recs: Vec<&'a DevRec>,
    }
    let mut nodes: Vec<Node> = Vec::new();
    let mut ni: BTreeMap<String, usize> = BTreeMap::new();
    let mut services: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for d in devices {
        let iid = py_upper(&d.id);
        if !starts(&iid, "BTHENUM\\") && !starts(&iid, "BTHLE\\") {
            continue;
        }
        let Some(m) = rx_btmac().search(iid.as_bytes(), 0) else {
            if let Some(gm) = rx_gm().match_(iid.as_bytes(), 0) {
                if let Some(mac) = rx_macr().search(iid.as_bytes(), 0) {
                    services
                        .entry(mac.group(1))
                        .or_default()
                        .insert(lower_ascii(&gm.group(1)));
                }
            }
            continue;
        };
        let mac = upper_ascii(&m.group(1));
        let kind = if starts(&iid, "BTHLE\\") {
            "BLE (düşük enerji)"
        } else {
            "Klasik"
        };
        let idx = match ni.get(&mac) {
            Some(i) => *i,
            None => {
                ni.insert(mac.clone(), nodes.len());
                nodes.push(Node {
                    mac: mac.clone(),
                    kinds: BTreeSet::new(),
                    recs: Vec::new(),
                });
                nodes.len() - 1
            }
        };
        nodes[idx].kinds.insert(kind.to_string());
        nodes[idx].recs.push(d);
    }
    for kv in reg {
        if !ni.contains_key(kv.0) {
            ni.insert(kv.0.clone(), nodes.len());
            nodes.push(Node {
                mac: kv.0.clone(),
                kinds: BTreeSet::from(["Klasik".to_string()]),
                recs: Vec::new(),
            });
        }
    }
    let mut out: Vec<BtDev> = Vec::new();
    *older = 0;
    for n in &nodes {
        let rg = reg.get(&n.mac);
        let mut name = rg.map(|r| r.name.clone()).unwrap_or_default();
        if name.is_empty() {
            for r in &n.recs {
                if !r.str("FriendlyName").is_empty() {
                    name = r.str("FriendlyName");
                    break;
                }
            }
        }
        if name.is_empty() {
            for r in &n.recs {
                if !r.str("DeviceDesc").is_empty() {
                    name = r.str("DeviceDesc");
                    break;
                }
            }
        }
        if name.is_empty() {
            name = mac_fmt(&n.mac);
        }
        let best = |key: &str, use_max: bool| -> OptT {
            let mut b: OptT = None;
            for r in &n.recs {
                let Some(t) = r.time(key) else { continue };
                if b.is_none_or(|bv| if use_max { t > bv } else { t < bv }) {
                    b = Some(t);
                }
            }
            b
        };
        let rg_lc = rg.and_then(|r| r.last_connected);
        let last_conn = if rg_lc.is_some() {
            rg_lc
        } else {
            best("BtLastConnected", true)
        };
        let conn_src = if rg_lc.is_some() {
            "Kayıt defteri (BTHPORT)"
        } else if last_conn.is_some() {
            "Aygıt Yöneticisi (Bluetooth son bağlantı)"
        } else {
            ""
        };
        let mut first = best("FirstInstallDate", false);
        if first.is_none() {
            first = best("InstallDate", false);
        }
        let recent = matches!(last_conn, Some(l) if l >= cutoff) || matches!(first, Some(f) if f >= cutoff);
        if !recent {
            *older += 1;
            continue;
        }
        let mut cat = String::new();
        if let Some(cod) = rg.and_then(|r| r.cod) {
            if let Some(v) = cod_major(((cod >> 8) & 0x1F) as i32) {
                cat = v.to_string();
            }
        }
        if cat.is_empty() {
            let classes: BTreeSet<String> = n.recs.iter().map(|r| py_lower(&r.str("Class"))).collect();
            if classes.contains("hidclass") {
                cat = "Giriş aygıtı (HID)".to_string();
            } else if classes.contains("media") || classes.contains("audioendpoint") {
                cat = "Ses aygıtı".to_string();
            }
        }
        let mut b = BtDev::default();
        if let Some(sset) = services.get(&n.mac) {
            for s in sset {
                let bs = bt_service(s);
                b.services.push(bs.map(|x| x.to_string()).unwrap_or_else(|| s.clone()));
                if s == "00001105" || s == "00001106" {
                    b.file_transfer_services.push(bs.unwrap_or_default().to_string());
                }
            }
        }
        if rg.is_some() {
            b.source.push("Kayıt defteri (BTHPORT)".to_string());
        }
        if !n.recs.is_empty() {
            b.source.push("Aygıt Yöneticisi (SetupAPI)".to_string());
        }
        b.name = name;
        b.mac = mac_fmt(&n.mac);
        let kinds: StrList = n.kinds.iter().cloned().collect();
        b.r#type = join(&kinds, " + ");
        b.category = cat;
        b.last_connected = last_conn;
        b.last_connected_source = conn_src.to_string();
        b.first_install = first;
        b.new_in_period = matches!(first, Some(f) if f >= cutoff);
        out.push(b);
    }
    let key = |x: &BtDev| -> f64 {
        let mut mx = -1e300_f64;
        let mut any = false;
        for t in [x.last_connected, x.first_install].into_iter().flatten() {
            mx = mx.max(t);
            any = true;
        }
        if any {
            mx
        } else {
            86400.0
        }
    };
    out.sort_by(|a, b| key(b).partial_cmp(&key(a)).unwrap_or(std::cmp::Ordering::Equal));
    out
}

struct Pk {
    name: &'static str,
    g: GUID,
    pid: u32,
}

#[allow(clippy::too_many_arguments)]
fn mkguid(a: u32, b: u16, c: u16, d: [u8; 8]) -> GUID {
    GUID::from_values(a, b, c, d)
}

fn keys() -> &'static Vec<Pk> {
    static K: OnceLock<Vec<Pk>> = OnceLock::new();
    K.get_or_init(|| {
        let dev = mkguid(
            0xa45c254e,
            0xdf1c,
            0x4efd,
            [0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0],
        );
        let dev2 = mkguid(
            0x540b947e,
            0x8b40,
            0x45bc,
            [0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2],
        );
        let par = mkguid(
            0x4340a6c5,
            0x93fa,
            0x4706,
            [0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7],
        );
        let cont = mkguid(
            0x8c7ed206,
            0x3f8a,
            0x4827,
            [0xb3, 0xab, 0xae, 0x9e, 0x1f, 0xae, 0xfc, 0x6c],
        );
        let inst = mkguid(
            0x83da6326,
            0x97a6,
            0x4088,
            [0x94, 0x53, 0xa1, 0x92, 0x3f, 0x57, 0x3b, 0x29],
        );
        let bt = mkguid(
            0x2bd67d8b,
            0x8beb,
            0x48d5,
            [0x87, 0xe0, 0x6c, 0xda, 0x34, 0x28, 0x04, 0x0a],
        );
        let pk = |name, g, pid| Pk { name, g, pid };
        vec![
            pk("DeviceDesc", dev, 2),
            pk("HardwareIds", dev, 3),
            pk("Service", dev, 6),
            pk("Class", dev, 9),
            pk("Manufacturer", dev, 13),
            pk("FriendlyName", dev, 14),
            pk("BusReportedDeviceDesc", dev2, 4),
            pk("IsPresent", dev2, 5),
            pk("Parent", par, 8),
            pk("ContainerId", cont, 2),
            pk("InLocalMachineContainer", cont, 4),
            pk("InstallDate", inst, 100),
            pk("FirstInstallDate", inst, 101),
            pk("LastArrivalDate", inst, 102),
            pk("LastRemovalDate", inst, 103),
            pk("BtAddress", bt, 1),
            pk("BtLastConnected", bt, 11),
        ]
    })
}

fn decode_prop(ptype: u32, raw: &[u8], now: f64) -> PropVal {
    let mut v = PropVal::default();
    let n = raw.len();
    match ptype {
        0x12 => {
            let mut s = utf16_decode(raw, true, 0);
            if let Some(z) = s.find('\0') {
                s.truncate(z);
            }
            v.k = PropKind::Str;
            v.s = s;
        }
        0x2012 => {
            let s = utf16_decode(raw, true, 0);
            v.k = PropKind::List;
            for x in s.split('\0') {
                if !x.is_empty() {
                    v.list.push(x.to_string());
                }
            }
        }
        0x10 if n >= 8 => {
            v.k = PropKind::Time;
            v.t = ft_dt(rd64(raw), now);
        }
        0x11 if n >= 1 => {
            v.k = PropKind::Bool;
            v.b = raw[0] != 0;
        }
        0x07 if n >= 4 => {
            v.k = PropKind::U32;
            v.u = rd32(raw);
        }
        0x0D if n >= 16 => {
            v.k = PropKind::Guid;
            v.s = format!(
                "{{{:08x}-{:04x}-{:04x}-{}-{}}}",
                rd32(raw),
                rd16(&raw[4..]),
                rd16(&raw[6..]),
                hex_lower(&raw[8..10]),
                hex_lower(&raw[10..16])
            );
        }
        _ => {}
    }
    v
}

fn wide_z(s: &str) -> Vec<u16> {
    let mut w = widen(s);
    if w.last() != Some(&0) {
        w.push(0);
    }
    w
}

fn enumerate_devices(present_only: bool, ids_only: bool, now: f64) -> Result<Vec<DevRec>, String> {
    let mut out: Vec<DevRec> = Vec::new();
    let mut flags = DIGCF_ALLCLASSES;
    if present_only {
        flags |= DIGCF_PRESENT;
    }
    // SAFETY: boş sınıf / numaralandırıcı; dönen tanıtıcı aşağıda yok edilir.
    let h = match unsafe { SetupDiGetClassDevsW(None, PCWSTR::null(), Some(HWND::default()), flags) } {
        Ok(h) => h,
        Err(_) => {
            // SAFETY: yalnızca son hata kodunu okur.
            let e = unsafe { GetLastError() }.0;
            return Err(format!("SetupDiGetClassDevs başarısız (hata {})", e));
        }
    };
    let mut pbuf: Vec<u8> = vec![0; 4096];
    for idx in 0..100000u32 {
        let mut did = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: did, cbSize ayarlı geçerli bir yapıdır.
        if unsafe { SetupDiEnumDeviceInfo(h, idx, &mut did) }.is_err() {
            break;
        }
        let mut idb = [0u16; 1024];
        let mut req = 0u32;
        // SAFETY: idb 1024 öğelik yazılabilir tampondur.
        if unsafe { SetupDiGetDeviceInstanceIdW(h, &did, Some(&mut idb), Some(&mut req)) }.is_err() {
            continue;
        }
        let len = idb.iter().position(|&c| c == 0).unwrap_or(idb.len());
        let mut rec = DevRec {
            id: narrow(&idb[..len]),
            ..Default::default()
        };
        if !ids_only {
            for k in keys() {
                let key = DEVPROPKEY { fmtid: k.g, pid: k.pid };
                let mut pt = DEVPROPTYPE(0);
                let mut rq = 0u32;
                // SAFETY: pbuf yazılabilir; pt / rq geçerli çıktı işaretçileri.
                let r =
                    unsafe { SetupDiGetDevicePropertyW(h, &did, &key, &mut pt, Some(&mut pbuf[..]), Some(&mut rq), 0) };
                if r.is_err() {
                    if rq as usize > pbuf.len() && rq < 1_000_000 {
                        let mut big = vec![0u8; rq as usize];
                        let mut rq2 = rq;
                        // SAFETY: big, rq bayt boyutundadır.
                        let r2 = unsafe {
                            SetupDiGetDevicePropertyW(h, &did, &key, &mut pt, Some(&mut big[..]), Some(&mut rq2), 0)
                        };
                        if r2.is_ok() {
                            let n = (rq2 as usize).min(big.len());
                            rec.props.insert(k.name.to_string(), decode_prop(pt.0, &big[..n], now));
                        }
                    }
                    continue;
                }
                let n = (rq as usize).min(pbuf.len());
                rec.props.insert(k.name.to_string(), decode_prop(pt.0, &pbuf[..n], now));
            }
        }
        out.push(rec);
    }
    // SAFETY: h, SetupDiGetClassDevsW'den gelen geçerli bir tanıtıcıdır.
    let _ = unsafe { SetupDiDestroyDeviceInfoList(h) };
    Ok(out)
}

struct RegVal {
    ty: u32,
    data: Bytes,
}

const KEY_FLAGS: REG_SAM_FLAGS = REG_SAM_FLAGS(KEY_READ.0 | KEY_WOW64_64KEY.0);

fn reg_values(root: HKEY, path: &str) -> BTreeMap<String, RegVal> {
    let mut out: BTreeMap<String, RegVal> = BTreeMap::new();
    let wp = wide_z(path);
    let mut k = HKEY::default();
    // SAFETY: wp NUL sonlu; k geçerli çıktı işaretçisi.
    if unsafe { RegOpenKeyExW(root, PCWSTR(wp.as_ptr()), None, KEY_FLAGS, &mut k) } != ERROR_SUCCESS {
        return out;
    }
    let mut i = 0u32;
    loop {
        let mut name = vec![0u16; 16384];
        let mut nl = 16384u32;
        let mut ty = 0u32;
        let mut dl = 0u32;
        // SAFETY: name 16384 öğelik tampon; veri tamponu verilmez (yalnızca boyut sorgusu).
        let r = unsafe {
            RegEnumValueW(
                k,
                i,
                Some(PWSTR(name.as_mut_ptr())),
                &mut nl,
                None,
                Some(&mut ty),
                None,
                Some(&mut dl),
            )
        };
        if r != ERROR_SUCCESS {
            break;
        }
        i += 1;
        let mut data = vec![0u8; dl as usize];
        nl = 16384;
        // SAFETY: data, dl bayt boyutundadır.
        let r2 = unsafe {
            RegEnumValueW(
                k,
                i - 1,
                Some(PWSTR(name.as_mut_ptr())),
                &mut nl,
                None,
                Some(&mut ty),
                Some(data.as_mut_ptr()),
                Some(&mut dl),
            )
        };
        if r2 != ERROR_SUCCESS {
            continue;
        }
        data.truncate(dl as usize);
        let nm = narrow(&name[..(nl as usize).min(name.len())]);
        out.insert(nm, RegVal { ty, data });
    }
    // SAFETY: k açık bir anahtardır.
    let _ = unsafe { RegCloseKey(k) };
    out
}

fn reg_subkeys(root: HKEY, path: &str) -> StrList {
    let mut out: StrList = Vec::new();
    let wp = wide_z(path);
    let mut k = HKEY::default();
    // SAFETY: wp NUL sonlu; k geçerli çıktı işaretçisi.
    if unsafe { RegOpenKeyExW(root, PCWSTR(wp.as_ptr()), None, KEY_FLAGS, &mut k) } != ERROR_SUCCESS {
        return out;
    }
    let mut i = 0u32;
    loop {
        let mut name = [0u16; 512];
        let mut nl = 512u32;
        // SAFETY: name 512 öğelik tampon.
        let r = unsafe { RegEnumKeyExW(k, i, Some(PWSTR(name.as_mut_ptr())), &mut nl, None, None, None, None) };
        if r != ERROR_SUCCESS {
            break;
        }
        out.push(narrow(&name[..(nl as usize).min(name.len())]));
        i += 1;
    }
    // SAFETY: k açık bir anahtardır.
    let _ = unsafe { RegCloseKey(k) };
    out
}

fn reg_filetime(v: &RegVal, now: f64) -> OptT {
    if (v.ty == REG_QWORD.0 || v.ty == REG_BINARY.0 || v.ty == REG_DWORD.0) && v.data.len() >= 8 {
        return ft_dt(rd64(&v.data), now);
    }
    if v.ty == REG_DWORD.0 && v.data.len() >= 4 {
        return ft_dt(rd32(&v.data) as u64, now);
    }
    None
}

fn read_bt_registry(now: f64) -> BTreeMap<String, BtReg> {
    let mut out: BTreeMap<String, BtReg> = BTreeMap::new();
    let base = "SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices";
    for sk in reg_subkeys(HKEY_LOCAL_MACHINE, base) {
        if sk.len() != 12 {
            continue;
        }
        if !sk.bytes().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let vals = reg_values(HKEY_LOCAL_MACHINE, &format!("{}\\{}", base, sk));
        let mut rec = BtReg::default();
        if let Some(nm) = vals.get("Name") {
            if nm.ty == REG_SZ.0 || nm.ty == REG_EXPAND_SZ.0 {
                let mut s = utf16_decode(&nm.data, true, 0);
                if let Some(z) = s.find('\0') {
                    s.truncate(z);
                }
                rec.name = pystrip(&s);
            } else {
                let z = nm.data.iter().position(|&c| c == 0).unwrap_or(nm.data.len());
                rec.name = pystrip(&utf8_decode(&nm.data[..z], 0));
            }
        }
        if let Some(cod) = vals.get("COD") {
            if cod.ty == REG_DWORD.0 && cod.data.len() >= 4 {
                rec.cod = Some(rd32(&cod.data));
            }
        }
        if let Some(lc) = vals.get("LastConnected") {
            rec.last_connected = reg_filetime(lc, now);
        }
        if let Some(ls) = vals.get("LastSeen") {
            rec.last_seen = reg_filetime(ls, now);
        }
        out.insert(upper_ascii(&sk), rec);
    }
    out
}

fn bam_runs(now: f64) -> Vec<BtRun> {
    static R: OnceLock<Rx> = OnceLock::new();
    let r = R.get_or_init(|| Rx::new(r"\\fsquirt\.exe$", Rx::I));
    let mut out: Vec<BtRun> = Vec::new();
    for base in [
        "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        "SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
    ] {
        for sid in reg_subkeys(HKEY_LOCAL_MACHINE, base) {
            for (name, val) in reg_values(HKEY_LOCAL_MACHINE, &format!("{}\\{}", base, sid)) {
                if r.search(name.as_bytes(), 0).is_none() {
                    continue;
                }
                if let Some(t) = reg_filetime(&val, now) {
                    out.push(BtRun {
                        time: t,
                        path: name,
                        source: "BAM (kayıt defteri)".to_string(),
                    });
                }
            }
        }
    }
    out
}

fn query_dev_events(channel: &str, ids: &[i32], days: i32, err: &mut String) -> Vec<DevEvent> {
    let mut out: Vec<DevEvent> = Vec::new();
    let mut raw: Vec<RawEvent> = Vec::new();
    if !query_event_xml(channel, ids, days, 20000, &mut raw, err, None) {
        return out;
    }
    fn walk(n: &XNode, e: &mut DevEvent) {
        for k in &n.kids {
            if k.tag == "Data" && k.has_attr("Name") {
                let key = k.attr("Name");
                let mut dup = false;
                for kv in e.data.iter_mut() {
                    if kv.0 == key {
                        kv.1 = pystrip(&k.text);
                        dup = true;
                    }
                }
                if !dup {
                    e.data.push((key, pystrip(&k.text)));
                }
            }
            walk(k, e);
        }
    }
    for r in &raw {
        let Some(root) = r.root.as_deref() else { continue };
        let Some(sys) = root.child("System") else { continue };
        let (Some(tc), Some(eid)) = (sys.child("TimeCreated"), sys.child("EventID")) else {
            continue;
        };
        let Some(t) = parse_utc_iso(&tc.attr("SystemTime")) else {
            continue;
        };
        let mut e = DevEvent {
            time: t,
            id: c_atoi(&strip(&eid.text, WS_CHARS)),
            data: Vec::new(),
        };
        walk(root, &mut e);
        out.push(e);
    }
    out
}

fn c_atoi(s: &str) -> i32 {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        v = (v * 10 + (b[i] - b'0') as i64).min(i32::MAX as i64 + 1);
        i += 1;
    }
    let v = if neg { -v } else { v };
    v.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

pub fn scan_devices(days: i32, progress: Option<StrProgress>) -> DeviceResult {
    let mut res = DeviceResult {
        days,
        ..Default::default()
    };
    res.now = now_epoch();
    res.cutoff = res.now - days as f64 * 86400.0;
    res.supported = true;
    let step = |m: &str| {
        if let Some(p) = progress {
            p(m);
        }
    };
    step("Aygıt listesi okunuyor (Aygıt Yöneticisi)...");
    let mut devices: Vec<DevRec> = Vec::new();
    let mut present: BTreeSet<String> = BTreeSet::new();
    match enumerate_devices(false, false, res.now) {
        Ok(d) => {
            devices = d;
            match enumerate_devices(true, true, res.now) {
                Ok(p) => {
                    for d in p {
                        present.insert(py_upper(&d.id));
                    }
                }
                Err(e) => res.errors.push(format!("Aygıt Yöneticisi okunamadı: {}", e)),
            }
        }
        Err(e) => res.errors.push(format!("Aygıt Yöneticisi okunamadı: {}", e)),
    }
    step("Olay günlükleri okunuyor...");
    let mut err = String::new();
    let pnp = query_dev_events(
        "Microsoft-Windows-Kernel-PnP/Configuration",
        &[400, 410],
        days,
        &mut err,
    );
    if !err.is_empty() {
        res.notes.push(format!(
            "Kernel-PnP olay günlüğü okunamadı (yönetici izni gerekebilir): {}",
            err
        ));
    }
    let mut err2 = String::new();
    let part = query_dev_events("Microsoft-Windows-Partition/Diagnostic", &[1006], days, &mut err2);
    step("USB aygıtları değerlendiriliyor...");
    res.usb = build_usb(
        &devices,
        &present,
        &pnp,
        &part,
        res.cutoff,
        &mut res.usb_internal_hidden,
    );
    step("Bluetooth aygıtları değerlendiriliyor...");
    let reg = read_bt_registry(res.now);
    res.bluetooth = build_bluetooth(&devices, &reg, res.cutoff, &mut res.bt_older);
    step("Bluetooth dosya aktarımı izleri aranıyor...");
    for r in bam_runs(res.now) {
        if r.time >= res.cutoff {
            res.bt_file_runs.push(r);
        }
    }
    let sr = env("SystemRoot");
    let pfd = path_join(if sr.is_empty() { "C:\\Windows" } else { &sr }, "Prefetch");
    let mut ents: Vec<DirEntry> = Vec::new();
    if list_dir(&pfd, &mut ents) {
        for e in &ents {
            let u = py_upper(&e.name);
            if starts(&u, "FSQUIRT.EXE-") && ends(&u, ".PF") && e.mtime >= res.cutoff {
                res.bt_file_runs.push(BtRun {
                    time: e.mtime,
                    path: e.path.clone(),
                    source: "Prefetch (son çalıştırma)".to_string(),
                });
            }
        }
    }
    let home = home_dir();
    let docs_list = [
        path_join(&home, "Documents"),
        path_join(&home, "Belgeler"),
        path_join_all(&[&home, "OneDrive", "Documents"]),
        path_join_all(&[&home, "OneDrive", "Belgeler"]),
    ];
    for docs in &docs_list {
        for sub in [
            "Bluetooth Exchange Folder",
            "Bluetooth Değişim Klasörü",
            "Bluetooth Değişim Klasörü",
        ] {
            let p = path_join(docs, sub);
            if !is_dir(&p) {
                continue;
            }
            let cutoff = res.cutoff;
            let files = &mut res.bt_files;
            walk_files(
                &p,
                &mut |fp: &str| {
                    let st = stat_path(fp, true);
                    if st.ok && st.mtime >= cutoff {
                        files.push(BtFile {
                            path: fp.to_string(),
                            time: st.mtime,
                            size: st.size,
                        });
                    }
                },
                2000000,
            );
        }
    }
    res.bt_file_runs
        .sort_by(|a, b| b.time.partial_cmp(&a.time).unwrap_or(std::cmp::Ordering::Equal));
    res.bt_files
        .sort_by(|a, b| b.time.partial_cmp(&a.time).unwrap_or(std::cmp::Ordering::Equal));
    if devices.is_empty() {
        res.notes.push(
            "Aygıt listesi boş döndü; program yönetici olarak çalıştırılırsa daha fazla kayıt okunur.".to_string(),
        );
    }
    res
}

pub fn bt_lines(r: &DeviceResult, header: bool) -> StrList {
    let mut l: StrList = Vec::new();
    let d = r.days;
    if header {
        l.push(format!("BLUETOOTH (son {} gün) - {} aygıt", d, r.bluetooth.len()));
    }
    for b in &r.bluetooth {
        let cat = if b.category.is_empty() {
            String::new()
        } else {
            format!(" - {}", b.category)
        };
        l.push(format!("  * {}  [{}]  {}{}", b.name, b.mac, b.r#type, cat));
        if b.last_connected.is_some() {
            l.push(format!(
                "      Son bağlantı : {}  ({})",
                fmt_dt(b.last_connected),
                b.last_connected_source
            ));
        }
        if b.first_install.is_some() {
            let extra = if b.new_in_period {
                format!("  << SON {} GÜNDE YENİ EŞLEŞTİ", d)
            } else {
                String::new()
            };
            l.push(format!("      İlk eşleşme  : {}{}", fmt_dt(b.first_install), extra));
        }
        if !b.file_transfer_services.is_empty() {
            l.push(format!(
                "      Dosya aktarımı hizmeti: {}",
                join(&b.file_transfer_services, ", ")
            ));
        }
        if !b.services.is_empty() {
            l.push(format!("      Hizmetler    : {}", join(&b.services, ", ")));
        }
        l.push(format!("      Kaynak       : {}", join(&b.source, ", ")));
    }
    if header && r.bt_older != 0 {
        l.push(format!(
            "  ({} eşleşmiş aygıtın son {} günde kaydı yok - gösterilmedi)",
            r.bt_older, d
        ));
    }
    l
}

pub fn bt_file_lines(r: &DeviceResult, header: bool) -> StrList {
    let mut l: StrList = Vec::new();
    if header {
        l.push(format!("BLUETOOTH DOSYA AKTARIMI (son {} gün)", r.days));
    }
    if r.bt_file_runs.is_empty() && r.bt_files.is_empty() {
        l.push("  Kayıt yok.".to_string());
    }
    for x in &r.bt_file_runs {
        l.push(format!(
            "  * Bluetooth Dosya Aktarımı (fsquirt.exe) çalıştırıldı: {}  ({})",
            fmt_dt(Some(x.time)),
            x.source
        ));
    }
    for f in &r.bt_files {
        l.push(format!(
            "  * Alınan dosya: {}  ({}, {} bayt)",
            f.path,
            fmt_dt(Some(f.time)),
            f.size
        ));
    }
    l
}

pub fn usb_lines(r: &DeviceResult, header: bool) -> StrList {
    let mut l: StrList = Vec::new();
    let d = r.days;
    if header {
        l.push(format!(
            "USB AYGITLARI (son {} gün + şu an takılı) - {} aygıt",
            d,
            r.usb.len()
        ));
    }
    for u in &r.usb {
        l.push(format!("  * {}  [{}]", u.name, u.state));
        l.push(format!("      İşlev        : {}", join(&u.functions, ", ")));
        let ser = if u.serial.is_empty() {
            String::new()
        } else {
            format!("   Seri: {}", u.serial)
        };
        l.push(format!("      VID/PID      : {} / {}{}", u.vid, u.pid, ser));
        if u.first_install.is_some() {
            let extra = if u.new_in_period {
                format!("  << SON {} GÜNDE İLK KEZ TAKILDI", d)
            } else {
                String::new()
            };
            l.push(format!("      İlk takılma  : {}{}", fmt_dt(u.first_install), extra));
        }
        if u.last_arrival.is_some() {
            l.push(format!(
                "      Son bağlanma : {} (takılma veya takılıyken açılış)",
                fmt_dt(u.last_arrival)
            ));
        }
        if u.last_removal.is_some() {
            l.push(format!("      Son çıkarılma: {}", fmt_dt(u.last_removal)));
        }
        for t in u.events.iter().take(15) {
            l.push(format!(
                "      Bağlantı olayı: {} (Windows aygıtı başlattı: takılma veya açılış)",
                fmt_dt(Some(*t))
            ));
        }
        for p in u.storage.iter().take(10) {
            let ser = if p.serial.is_empty() {
                String::new()
            } else {
                format!("seri {}", p.serial)
            };
            l.push(format!(
                "      Disk bağlandı: {}  {} {} {}",
                fmt_dt(Some(p.time)),
                p.model,
                p.capacity,
                ser
            ));
        }
        l.push(format!("      Aygıt kimliği: {}", u.id));
        l.push(format!("      Kaynak       : {}", join(&u.source, ", ")));
    }
    if header && r.usb_internal_hidden != 0 {
        l.push(format!(
            "  ({} dahili USB aygıtı - bilgisayarın kendi parçası - listelenmedi)",
            r.usb_internal_hidden
        ));
    }
    l
}

pub fn device_lines(r: &DeviceResult) -> StrList {
    let mut l = bt_lines(r, true);
    l.extend(bt_file_lines(r, true));
    l.extend(usb_lines(r, true));
    for n in &r.notes {
        l.push(format!("  Not: {}", n));
    }
    for e in &r.errors {
        l.push(format!("  Hata: {}", e));
    }
    l
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atoi_like_c() {
        assert_eq!(c_atoi("  400"), 400);
        assert_eq!(c_atoi("-5x"), -5);
        assert_eq!(c_atoi(""), 0);
        assert_eq!(c_atoi("99999999999"), i32::MAX);
    }

    #[test]
    fn decode_basic_props() {
        let now = 4_000_000_000.0;
        let raw: Vec<u8> = "Ab\0cd".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let v = decode_prop(0x12, &raw, now);
        assert_eq!(v.k, PropKind::Str);
        assert_eq!(v.s, "Ab");
        let v = decode_prop(0x11, &[1], now);
        assert!(v.b);
        let v = decode_prop(0x07, &[1, 0, 0, 0], now);
        assert_eq!(v.u, 1);
        assert_eq!(decode_prop(0x07, &[1], now).k, PropKind::None);
        let v = decode_prop(0x2012, &raw, now);
        assert_eq!(v.list, vec!["Ab".to_string(), "cd".to_string()]);
        let g: Vec<u8> = (0u8..16).collect();
        let v = decode_prop(0x0D, &g, now);
        assert_eq!(v.s, "{03020100-0504-0706-0809-0a0b0c0d0e0f}");
    }

    fn dev(id: &str, props: &[(&str, PropVal)]) -> DevRec {
        DevRec {
            id: id.to_string(),
            props: props.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        }
    }
    fn sp(s: &str) -> PropVal {
        PropVal {
            k: PropKind::Str,
            s: s.to_string(),
            ..Default::default()
        }
    }
    fn tp(t: f64) -> PropVal {
        PropVal {
            k: PropKind::Time,
            t: Some(t),
            ..Default::default()
        }
    }

    #[test]
    fn usb_build() {
        let usb = dev(
            "USB\\VID_046D&PID_C52B\\ABC123",
            &[("Class", sp("USB")), ("FirstInstallDate", tp(2_000_000_000.0))],
        );
        let child = dev(
            "USBSTOR\\DISK&VEN_X\\1",
            &[
                ("Parent", sp("USB\\VID_046D&PID_C52B\\ABC123")),
                ("Class", sp("DiskDrive")),
                ("FriendlyName", sp("Test Disk")),
            ],
        );
        let mut present = BTreeSet::new();
        present.insert("USB\\VID_046D&PID_C52B\\ABC123".to_string());
        let mut hidden = 0;
        let r = build_usb(&[usb, child], &present, &[], &[], 1_900_000_000.0, &mut hidden);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].name, "Test Disk");
        assert_eq!(r[0].vid, "046D");
        assert_eq!(r[0].pid, "C52B");
        assert_eq!(r[0].serial, "ABC123");
        assert_eq!(r[0].state, "ŞU AN TAKILI");
        assert!(r[0].new_in_period);
        assert_eq!(r[0].functions, vec!["Depolama (USB bellek / harici disk)".to_string()]);
    }

    #[test]
    fn bt_build() {
        let d = dev(
            "BTHENUM\\DEV_AABBCCDDEEFF\\7&1&0&BLUETOOTHDEVICE_AABBCCDDEEFF",
            &[
                ("FriendlyName", sp("Kulaklık")),
                ("FirstInstallDate", tp(2_000_000_000.0)),
            ],
        );
        let mut older = 0;
        let r = build_bluetooth(&[d], &BTreeMap::new(), 1_900_000_000.0, &mut older);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].mac, "AA:BB:CC:DD:EE:FF");
        assert_eq!(r[0].r#type, "Klasik");
        assert_eq!(older, 0);
    }

    #[test]
    fn lines_format() {
        let mut r = DeviceResult::default();
        r.bt_file_runs.push(BtRun::default());
        assert_eq!(bt_file_lines(&r, true)[0], "BLUETOOTH DOSYA AKTARIMI (son 5 gün)");
        assert_eq!(mac_fmt("aabbccddeeff"), "AA:BB:CC:DD:EE:FF");
    }
}
