// gui_lora_pq.rs – ZorroChain Test Demo (LoRa + Dilithium5 / SPHINCS+)
// build: cargo run --release --bin gui_lora_pq --features gui

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use chrono;
use eframe::egui::{self, Color32, RichText};
use rfd::FileDialog;
use serialport::{SerialPort, SerialPortInfo};
use std::{
    io::{Read, Write},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

#[path = "../crypto.rs"]
mod crypto;
use crypto::*; // HybridSigner, Packet, verify_hybrid
// -----------------------------------------------------------------------------
// GUI state
// -----------------------------------------------------------------------------
struct AppState {
    port_list:     Vec<SerialPortInfo>,
    selected_port: Option<String>,
    port_handle:   Arc<Mutex<Option<Box<dyn SerialPort>>>>,

    username: String,
    log:      Arc<Mutex<Vec<(String, Color32)>>>,
    rssi:     Arc<Mutex<Option<i16>>>,
    peer_ok:  Arc<Mutex<bool>>,

    tx_cmd: Sender<GuiCmd>,
}
enum GuiCmd {
    Open(String),
    Send(Vec<u8>, String), // data, filename
    Shutdown,
}

// -----------------------------------------------------------------------------
// Several tiny helpers for the dongle’s “AT” escape
// -----------------------------------------------------------------------------
fn enter_at_mode(port: &mut dyn SerialPort) -> std::io::Result<()> {
    port.write_all(b"+++")?;
    port.flush()?;
    thread::sleep(Duration::from_millis(1000)); // ★ 1 s guard
    Ok(())
}
fn exit_at_mode(port: &mut dyn SerialPort) -> std::io::Result<()> {
    port.write_all(b"ATO\r\n")?;
    port.flush()?;
    thread::sleep(Duration::from_millis(50));
    Ok(())
}

// -----------------------------------------------------------------------------
// Tiny self-framing helpers for the keep-alive
// -----------------------------------------------------------------------------
const PING: &[u8; 4] = b"PING";
const PONG: &[u8; 4] = b"PONG";

fn send_framed(port: &mut dyn SerialPort, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len() as u16;
    port.write_all(&len.to_le_bytes())?;
    port.write_all(payload)?;
    Ok(())
}

// read a complete length-prefixed frame (None = timeout)
fn recv_frame(port: &mut dyn SerialPort) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 2];
    match port.read_exact(&mut len_buf) {
        Ok(()) => {
            let len = u16::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            port.read_exact(&mut buf)?;
            Ok(Some(buf))
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
        Err(e) => Err(e.into()),
    }
}

// -----------------------------------------------------------------------------
// AppState impl
// -----------------------------------------------------------------------------
impl AppState {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel::<GuiCmd>();
        let log      = Arc::new(Mutex::new(Vec::new()));
        let port_h   = Arc::new(Mutex::new(None));
        let rssi     = Arc::new(Mutex::new(None));
        let peer_ok  = Arc::new(Mutex::new(false));

        start_lora_thread(rx, log.clone(), port_h.clone(), rssi.clone(), peer_ok.clone());

        Self {
            port_list: serialport::available_ports().unwrap_or_default(),
            selected_port: None,
            port_handle: port_h,
            username: "Alice".into(),
            log,
            rssi,
            peer_ok,
            tx_cmd: tx,
        }
    }
    fn push_log(&self, msg: &str, col: Color32) {
        self.log.lock().unwrap().push((msg.to_owned(), col));
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // -------- top bar
        egui::TopBottomPanel::top("bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Username:");
                ui.text_edit_singleline(&mut self.username);
                ui.separator();

                ui.label("Port:");
                egui::ComboBox::from_id_source("ports")
                    .selected_text(self.selected_port.clone().unwrap_or_else(|| "Select".into()))
                    .show_ui(ui, |ui| {
                        for p in &self.port_list {
                            ui.selectable_value(&mut self.selected_port, Some(p.port_name.clone()), &p.port_name);
                        }
                    });
                if ui.button("Open").clicked() {
                    if let Some(ref pn) = self.selected_port {
                        let _ = self.tx_cmd.send(GuiCmd::Open(pn.clone()));
                    }
                }
                if ui.button("Rescan").clicked() {
                    self.port_list = serialport::available_ports().unwrap_or_default();
                }
                ui.separator();

                if ui.button("Send file …").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() {
                        if let Ok(data) = std::fs::read(&path) {
                            let fname = path.file_name().unwrap().to_string_lossy().into_owned();
                            let _ = self.tx_cmd.send(GuiCmd::Send(data, fname));
                        }
                    }
                }

                ui.separator();
                // live RSSI
                let r_txt = self
                    .rssi
                    .lock()
                    .unwrap()
                    .map(|v| format!("RSSI {v} dBm"))
                    .unwrap_or_else(|| "RSSI —".into());
                ui.label(r_txt);
                // peer badge
                let p_col = if *self.peer_ok.lock().unwrap() { Color32::LIGHT_GREEN } else { Color32::RED };
                ui.colored_label(p_col, "Peer");
            });
        });

        // -------- log
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (msg, col) in self.log.lock().unwrap().iter() {
                    ui.label(RichText::new(msg).color(*col));
                }
            });
        });

        ctx.request_repaint_after(Duration::from_millis(120));
    }
}

// -----------------------------------------------------------------------------
// LoRa worker thread
// -----------------------------------------------------------------------------
fn start_lora_thread(
    rx:        Receiver<GuiCmd>,
    log:       Arc<Mutex<Vec<(String, Color32)>>>,
    port_h:    Arc<Mutex<Option<Box<dyn SerialPort>>>>,
    rssi_out:  Arc<Mutex<Option<i16>>>,
    peer_flag: Arc<Mutex<bool>>,
) {
    thread::spawn(move || {
        let mut cur: Option<Box<dyn SerialPort>> = None;
        let mut last_rssi = Instant::now();
        let mut last_ping = Instant::now();

        loop {
            // 1) handle GUI commands -------------------------------------------------
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    GuiCmd::Open(path) => {
                        match serialport::new(&path, 9600).timeout(Duration::from_millis(500)).open() {
                            Ok(p) => {
                                log.lock().unwrap().push((format!("✅ opened {path}"), Color32::LIGHT_GREEN));
                                cur = Some(p);
                                *port_h.lock().unwrap() = None; // not shared elsewhere
                            }
                            Err(e) => log.lock().unwrap().push((format!("❌ {e}"), Color32::RED)),
                        }
                    }
                    GuiCmd::Send(data, fname) => {
                        if let Some(ref mut p) = cur {
                            if let Err(e) = send_packet(&mut **p, &data, &fname) {
                                log.lock().unwrap().push((format!("❌ send: {e}"), Color32::RED))
                            } else {
                                log.lock().unwrap().push((format!("📤 sent {fname} ({} B)", data.len()), Color32::LIGHT_BLUE))
                            }
                        }
                    }
                    GuiCmd::Shutdown => return,
                }
            }

            // no port → sleep
            let Some(ref mut port) = cur else {
                thread::sleep(Duration::from_millis(60));
                continue;
            };

            // 2) periodic RSSI -------------------------------------------------------
            if last_rssi.elapsed() >= Duration::from_secs(1) {
                if enter_at_mode(&mut **port).is_ok() {
                    if port.write_all(b"AT+RSSI?\r\n").is_ok() {
                        let mut buf = [0u8; 32];
                        if let Ok(n) = port.read(&mut buf) {
                            if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                                if let Some(v) = s.trim().strip_prefix("+RSSI:") {
                                    if let Ok(dbm) = v.trim().parse::<i16>() {
                                        *rssi_out.lock().unwrap() = Some(dbm);
                                    }
                                }
                            }
                        }
                    }
                    let _ = exit_at_mode(&mut **port);
                }
                last_rssi = Instant::now();
            }

            // 3) keep-alive ping -----------------------------------------------------
            if last_ping.elapsed() >= Duration::from_secs(3) {
                let _ = send_framed(&mut **port, PING);
                *peer_flag.lock().unwrap() = false;
                last_ping = Instant::now();
            }

            // 4) incoming ------------------------------------------------------------
            if let Ok(Some(frame)) = recv_frame(&mut **port) {
                // ---- incoming frame --------------------------------------------------
if frame == PING {
    // got PING  → send PONG
    let _ = send_framed(&mut **port, PONG);
} else if frame == PONG {
    // got PONG  → peer alive
    *peer_flag.lock().unwrap() = true;
} else {
    // otherwise try to parse as a signed Packet
    if let Ok(pkt) = serde_json::from_slice::<Packet>(&frame) {
        if verify_hybrid(&pkt).unwrap_or(false) {
            if let Ok(raw) = general_purpose::STANDARD.decode(&pkt.data) {
                std::fs::write(&pkt.filename, &raw).ok();
                log.lock().unwrap().push((
                    format!("📥 recv {} ({} B)", pkt.filename, raw.len()),
                    Color32::YELLOW,
                ));
            }
        }
    }
}

            }

            thread::sleep(Duration::from_millis(40));
        }
    });
}

// -----------------------------------------------------------------------------
// send a signed Packet
// -----------------------------------------------------------------------------
fn send_packet(port: &mut dyn SerialPort, data: &[u8], fname: &str) -> Result<()> {
    let signer = HybridSigner::new();
    let pkt = Packet {
        data: general_purpose::STANDARD.encode(data),
        sig: signer.sign(data),
        pubkey: signer.export_public(),
        filename: fname.into(),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    let bytes = serde_json::to_vec(&pkt)?;
    send_framed(port, &bytes)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------
fn main() {
    let opts = eframe::NativeOptions::default();
    let _ = eframe::run_native(
        "ZorroChain Test Demo",
        opts,
        Box::new(|cc| Box::new(AppState::new(cc))),
    );
}
