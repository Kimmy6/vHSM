"""Example Raspberry Pi gateway.
Run this on the Pi, then let the Android app send START_USER_CONNECT:<userId>
through Bluetooth RFCOMM, TCP, or any other transport you choose.

This file keeps the transport layer on the Pi side in Python.
The real terminal output is shown in LXTerminal, not in the phone app.
"""

from __future__ import annotations

import os
import socket
import subprocess

HOST = "0.0.0.0"
PORT = 5000
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
TERMINAL_SCRIPT = os.path.join(PROJECT_ROOT, "user_connect_terminal.py")


def launch_terminal_for_user(user_id: str) -> None:
    command = [
        "lxterminal",
        "-e",
        f'python3 "{TERMINAL_SCRIPT}" "{user_id}"',
    ]
    subprocess.Popen(command)


def handle_command(command: str) -> str:
    command = command.strip()

    if command.startswith("START_USER_CONNECT:"):
        user_id = command.split(":", 1)[1].strip() or "User"
        launch_terminal_for_user(user_id)
        return "OK"

    return "UNKNOWN_COMMAND"


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"Pi gateway listening on {HOST}:{PORT}")

        while True:
            conn, _addr = server.accept()
            with conn:
                data = conn.recv(1024).decode("utf-8", errors="ignore")
                reply = handle_command(data)
                conn.sendall(reply.encode("utf-8"))


if __name__ == "__main__":
    main()
