#!/usr/bin/env python3
# esp32_mock.py — ESP32 UART 흉내 (pty echo 수정 버전)

import os
import pty
import time
import threading
import termios

FAKE_KEY_HEX = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"

def main():
    master_fd, slave_fd = pty.openpty()

    # ── pty echo 완전히 비활성화 ─────────────────────────────
    # echo가 켜져 있으면 master가 쓴 내용이 master에게 되돌아와
    # mock이 자기가 보낸 READY를 "Pi가 보낸 것"으로 착각함
    attrs = termios.tcgetattr(slave_fd)
    attrs[3] &= ~(termios.ECHO | termios.ECHOE |
                  termios.ECHOK | termios.ECHONL)
    attrs[3] &= ~termios.ICANON
    termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)

    slave_path = os.ttyname(slave_fd)
    print("=" * 52)
    print(f"[MOCK] 가상 포트: {slave_path}")
    print(f"[MOCK] tcp_server.py 에서 임시 변경:")
    print(f'[MOCK]   ESP32_PORT = "{slave_path}"')
    print("=" * 52)

    # READY 주기 전송 (master에 씀 → tcp_server가 slave에서 읽음)
    def send_ready():
        while True:
            try:
                os.write(master_fd, b"READY\r\n")
                print("[MOCK] ESP32 → Pi: READY")
            except OSError:
                break
            time.sleep(2)

    threading.Thread(target=send_ready, daemon=True).start()

    # Pi 입력 수신 (master에서 읽음 → tcp_server가 slave에 쓴 것)
    buf = b""
    while True:
        try:
            ch = os.read(master_fd, 1)
        except OSError:
            break

        if ch == b"\n":
            line = buf.decode("utf-8", errors="ignore").strip()
            buf = b""
            if not line:
                continue
            print(f"[MOCK] Pi → ESP32: '{line}'")
            if "G" in line:
                print("[MOCK] 'G' 수신 → 캡처 시뮬레이션 (1초)...")
                time.sleep(1)
                resp = f"KEY_HEX:{FAKE_KEY_HEX}\r\nDONE\r\n".encode()
                os.write(master_fd, resp)
                print(f"[MOCK] ESP32 → Pi: KEY_HEX:{FAKE_KEY_HEX}")
        elif ch != b"\r":
            buf += ch

if __name__ == "__main__":
    main()