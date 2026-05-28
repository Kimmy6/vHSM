# vHSM Project

Research-grade Virtual HSM for academic publication. Comparative target: Thales Luna K7 FIPS 140-3.

## Architecture
- **Layer 1 (MCU):** STM32L432KC (E-PUF) + ESP32-CAM (O-PUF) — all crypto here, keys never leave MCU
- **Layer 2 (Server):** RPi4 OS Lite — TLS 1.3 TCP relay only, treated as untrusted
- **Layer 3 (Client):** Android (Qt6/QML)

## Crypto Stack
ML-DSA-65 (FIPS 204) · Shortened BCH Fuzzy Extractor · HKDF (RFC 5869) · AES-192 · TLS 1.3 (RFC 8446)

## File Paths — CRITICAL
- **ESP32-CAM firmware MUST be edited at:** `5.3.1_rip version_code only/esp32_cam_puf/main/`
- **NEVER edit** `D:\Develop\esp32_cam_puf\` (root repo — wrong location)
- Pi backend: `5.3.1_rip version_code only/pi_backend-v6/tcp_server.py`
- Qt client: `5.3.1_rip version_code only/src/`

## Key Design Rules
- ML-DSA is NOT in RFC 8446 §4.4.3 → TLS uses ECDSA; ML-DSA runs at application layer (challenge-response)
- RPi serial UART: use `os.open()` + `O_NONBLOCK`, not pyserial (breaks stty termios)
- ESP32-CAM capture: two-phase (JPEG → deinit → GRAYSCALE) to avoid PSRAM conflict; `camera_power_cycle()` before each init
- UART trigger: ESP32 sends "READY\r\n" every 200ms; Pi sends "GO\r\n"; ESP32 replies "GO_RECEIVED\r\n" then "KEY_HEX:...\r\n" + "DONE\r\n"
- `esp_restart()` after each key transmission — ensures clean camera state for next capture
- `PUF_DEBUG_SAVE` compile flag in `image_capture.c` — comment out for production (no SD writes)
- All OV2640 sensor auto-processing disabled (AWB/AGC/AEC/BPC/WPC/GMA/LENC/DCW/denoise/sharpness); manual exposure = 100
- Entropy analysis uses **min-entropy**, not Shannon (NIST SP 800-90B)
- Tamper response = helper data deletion, not PUF destruction

## DO NOT — Token Budget

**Never read these files/directories:**
- `build/` — ESP-IDF build artifacts (potentially hundreds of thousands of lines)
- `build-*/` — Qt build directories
- `*.bin`, `*.elf` — compiled firmware binaries
- `*.img`, `*.raw`, `*.jpg`, `*.pgm` — O-PUF captured images
- `sdkconfig` — grep for specific keys only, never read the whole file
- `__pycache__/`, `*.pyc`
- `.git/objects/`
- `*.log` — use `tail -n 50` or `grep` only

**Never do these:**
- Read an entire file before trying `grep`/`find` first — targeted search always wins
- Recursively read entire directories — specify only the files needed
- Re-read files already seen in the same session

## Current TODOs
- [ ] SD card pipeline for O-PUF artifacts
- [ ] Android certificate pinning
- [ ] Academic paper: threat model + comparative analysis sections

## Docs
See `docs/` for full crypto design, threat model, BCH params, and PKI/attestation details.
