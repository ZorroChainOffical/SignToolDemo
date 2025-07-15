<!--
DemosignTool – ZorroChain Entropy Signature Interface  
Copyright (c) 2025–present ZorroChain Foundation

Licensed under the Mozilla Public License, v. 2.0  
https://mozilla.org/MPL/2.0/
-->
<!--
@defgroup DemosignTool Entropy Signature Verifier & PQ Offline GUI
@ingroup ZorroChainCodex
A proof-ready offline signature relay for post-quantum civic payloads via LoRa, USB, and mesh transport.
-->

# 🛰️ `demosigntoolzorrochain/` – Offline Signature Relay & Post-Quantum Civic Toolkit

The `demosigntoolzorrochain/` module enables capture, verification, and encoding of post-quantum civic payloads  
using Dilithium and SPHINCS+ keyrings across LoRa, serial, or airgapped channels. It supports offline civic signing flows,  
mesh verification bursts, and GUI-assisted keypair operations — designed for field validators and node operators in disrupted zones.

---

## 🔹 Components

### `main.rs`  
- Orchestrates CLI/GUI feature branching and post-quantum signature lifecycle.  
- Initializes entropy, LoRa transport interface, and user challenge prompts.  
- Supports interactive signing or payload verification from serialized inputs.

### `crypto.rs`  
- Manages Dilithium5 and SPHINCS+ keypairs using the `pqcrypto` suite.  
- Encodes signatures and public keys in base64 and hex formats for LoRa broadcast.  
- Validates detached civic payloads and returns timestamped integrity state.

### `gui_lora_pq.rs`  
- Optional GUI shell (requires `--features gui`) for managing keypairs and verifying messages.  
- Integrates clipboard, USB, and serial-based payload injection with real-time validation prompts.  
- LoRa integration uses serialport relays with signature echo and alert feedback via notify-rust.

---

## 📝 Use Cases

- **Offline Signature Verification**: Validate detached civic payloads from mesh QR, USB, or LoRa sources.  
- **Post-Quantum Signing**: Generate SPHINCS+/Dilithium signatures using airgapped entropy and serialized challenge inputs.  
- **LoRa Civic Relays**: Transmit and verify civic proposals or identity packets across untrusted long-range mesh.  
- **Validator Field Tool**: Serve as a portable audit module for governance decisions or vault-authenticated ballots.

---

## ⚖️ Future Expansion

- **Epoch-Embedded Payload Signing**: Automate civic epoch attestation during signature challenge flows.  
- **Vault Integration**: Pipe identity-seeded entropy from VaultOS into the signing interface.  
- **Fingerprint-to-Sign Hook**: Optional biometric trigger for sign authority under field quorum context.  
- **Encrypted Message Batching**: Support multi-signed, LoRa-broadcastable civic documents with envelope proofs.

---

## ✨ Implementation Notes

- Supports fallback entropy injection via serial stream if biometric or Vault entropy is unavailable.  
- GUI shell operates independently via `eframe` and clipboard IO; CLI flows mirror logic for airgapped usage.  
- LoRa transport uses ASCII-safe signature encoding for minimal packet loss under mesh relays.  
- Signature integrity checked via real-time hash and base64 pattern heuristics.

---

## ⌛ Recent Changes

- **2025-07-14**: Initial civic signature GUI and CLI published with LoRa relay support.  
- **2025-07-13**: SPHINCS+ support finalized and broadcast encoder validated for USB/mesh.  
- **2025-07-10**: Project scaffolded and integrated with `pqcrypto-traits` entropy system.

---

> _“Not all signatures need servers. Some need only integrity and distance.”_
