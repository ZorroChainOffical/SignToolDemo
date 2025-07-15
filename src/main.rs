// gui_lora_pq.rs
// -----------------------------------------------------------------------------
// Minimal desktop GUI for the LoRa + hybrid‑PQ signing demo.
// Uses **eframe/egui** (cross‑platform: Windows, macOS, Linux). One window shows:
//   • Port selector + “Open” button (auto‑detects USB serial ports)
//   • Username textbox (so Alice/Bob know who is who)
//   • "Send File" button → file‑picker → signs & transmits
//   • Live log pane with coloured entries (info, success, error)
//   • LoRa status badge (green = port open, red = closed)
//   • Desktop notifications on successful send/receive
//
// Build & run:
//     cargo run --release --features gui
//
// -----------------------------------------------------------------------------
// Cargo.toml additions (under [features] add `gui = ["eframe", "rfd"]`)
// -----------------------------------------------------------------------------
// eframe              = { version = "0.27", optional = true }
// rfd                 = { version = "0.14", optional = true }   # file‑picker
// tokio               = { version = "1", features=["rt", "macros", "sync"], optional=true }
// notify‑rust         = { version = "4", optional=true, default-features = false, features=["toast"] }
// serialport          = "4.3"
// plus the same pqcrypto / base64 / serde / sha3 / anyhow crates as the CLI.
// -----------------------------------------------------------------------------

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console on Windows

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use eframe::egui::{self, Align, Color32, Layout, RichText};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_sphincsplus::sphincssha2256ssimple as sphincs;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SignedMessage as _};
use rfd::FileDialog;
use serialport::{SerialPort, SerialPortInfo};
use sha3::{Digest, Sha3_256};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

mod crypto;
use crypto::*; // re‑export structs from previous file (HybridSigner, verify_hybrid, Packet)

// ----------------------- GUI App State --------------------------------------
struct AppState {
    port_list: Vec<SerialPortInfo>,
    selected_port: Option<String>,
    port_handle: Arc<Mutex<Option<Box<dyn SerialPort>>>>,

    username: String,
    log: Arc<Mutex<Vec<(String, Color32)>>>,

    tx_cmd: Sender<GuiCmd>,
}

enum GuiCmd {
    Open(String),
    Send(Vec<u8>, String), // data, filename
    Shutdown,
}

impl AppState {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let (tx, rx) = channel::<GuiCmd>();
        let log = Arc::new(Mutex::new(Vec::new()));
        let port_handle = Arc::new(Mutex::new(None));

        // spawn background thread for LoRa I/O
        start_lora_thread(rx, log.clone(), port_handle.clone());

        // initial port scan
        let ports = serialport::available_ports().unwrap_or_default();

        Self {
            port_list: ports,
            selected_port: None,
            port_handle,
            username: String::from("Alice"),
            log,
            tx_cmd: tx,
        }
    }

    fn push_log(&self, msg: &str, colour: Color32) {
        self.log.lock().unwrap().push((msg.to_owned(), colour));
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Username:");
                ui.text_edit_singleline(&mut self.username);
                ui.separator();
                ui.label("Serial Port:");
                let port_names: Vec<String> = self
                    .port_list
                    .iter()
                    .map(|p| p.port_name.clone())
                    .collect();
                egui::ComboBox::from_id_source("portbox")
                    .selected_text(self.selected_port.clone().unwrap_or_else(|| "Select".into()))
                    .show_ui(ui, |ui| {
                        for p in &port_names {
                            ui.selectable_value(&mut self.selected_port, Some(p.clone()), p);
                        }
                    });
                if ui.button("Open").clicked() {
                    if let Some(ref pn) = self.selected_port {
                        self.tx_cmd.send(GuiCmd::Open(pn.clone())).ok();
                    }
                }
                if ui.button("Rescan").clicked() {
                    self.port_list = serialport::available_ports().unwrap_or_default();
                }

                ui.separator();
                if ui.button("Send File …").clicked() {
                    if let Some(path) = FileDialog::new().pick_file() {
                        if let Ok(data) = std::fs::read(&path) {
                            self.tx_cmd
                                .send(GuiCmd::Send(data, path.file_name().unwrap().to_string_lossy().into()))
                                .ok();
                        }
                    }
                }
            });
        });

        // log panel
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (msg, col) in self.log.lock().unwrap().iter() {
                    ui.horizontal(|ui| {
                        ui.add(egui::Label::new(RichText::new(msg).color(*col)));
                    });
                }
            });
        });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

// ------------------------ LoRa worker thread ---------------------------------
fn start_lora_thread(rx: Receiver<GuiCmd>, log: Arc<Mutex<Vec<(String, Color32)>>>, port_h: Arc<Mutex<Option<Box<dyn SerialPort>>>>) {
    thread::spawn(move || {
        let mut cur_port: Option<Box<dyn SerialPort>> = None;

        loop {
            // poll for GUI commands
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    GuiCmd::Open(path) => {
                        match serialport::new(&path, 9600).timeout(Duration::from_millis(500)).open() {
                            Ok(p) => {
                                log.lock().unwrap().push((format!("✅ opened {}", path), Color32::LIGHT_GREEN));
                                cur_port = Some(p);
                                *port_h.lock().unwrap() = cur_port.clone();
                            }
                            Err(e) => log.lock().unwrap().push((format!("❌ open {}: {}", path, e), Color32::RED)),
                        }
                    }
                    GuiCmd::Send(data, fname) => {
                        if let Some(ref mut p) = cur_port {
                            match send_packet(p, &data, &fname) {
                                Ok(_) => {
                                    log.lock().unwrap().push((format!("📤 sent {} ({} B)", fname, data.len()), Color32::LIGHT_BLUE));
                                    let _=notify_rust::Notification::new().summary("File sent").body(&fname).show();
                                }
                                Err(e) => log.lock().unwrap().push((format!("❌ send: {}", e), Color32::RED)),
                            }
                        }
                    }
                    GuiCmd::Shutdown => return,
                }
            }

            // poll for incoming frames if port open
            if let Some(ref mut p) = cur_port {
                if let Ok(Some(frame)) = recv_frame(p) {
                    if let Ok(pkt): Result<Packet> = serde_json::from_slice(&frame).map_err(|e| e.into()) {
                        if let Ok(true) = verify_hybrid(&pkt) {
                            let raw = general_purpose::STANDARD.decode(&pkt.data).unwrap();
                            std::fs::write(&pkt.filename, &raw).ok();
                            log.lock().unwrap().push((format!("📥 recv {} ({} B)", pkt.filename, raw.len()), Color32::YELLOW));
                            let _=notify_rust::Notification::new().summary("File received").body(&pkt.filename).show();
                        }
                    }
                }
            }

            thread::sleep(Duration::from_millis(50));
        }
    });
}

// ---------------------- minimal framing helpers -----------------------------
fn send_packet(port: &mut dyn SerialPort, data: &[u8], fname: &str) -> Result<()> {
    let signer = HybridSigner::new();
    let pkt = Packet {
        data: general_purpose::STANDARD.encode(data),
        sig: signer.sign(data),
        pubkey: signer.export_public(),
        filename: fname.into(),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };
    let json = serde_json::to_vec(&pkt)?;
    let len = json.len() as u16;
    port.write_all(&len.to_le_bytes())?;
    port.write_all(&json)?;
    Ok(())
}

fn recv_frame(port: &mut dyn SerialPort) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 2];
    match port.read_exact(&mut len_buf) {
        Ok(()) => {
            let len = u16::from_le_bytes(len_buf) as usize;
            let mut buf = vec![0u8; len];
            port.read_exact(&mut buf)?;
            Ok(Some(buf))
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
        Err(e) => Err(e.into()),
    }
}

// ------------------------------- main ---------------------------------------
fn main() -> Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "LoRa PQ File Transfer",
        native_options,
        Box::new(|cc| Box::new(AppState::new(cc))),
    )?;
    Ok(())
}

// This file is part of ZorroChain Core.
// Copyright (c) 2025 ZorroChain Foundation
// Licensed under the Mozilla Public License, v. 2.0
// See LICENSE.md in the root for full license text.
