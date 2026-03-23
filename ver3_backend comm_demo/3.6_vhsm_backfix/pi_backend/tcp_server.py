from __future__ import annotations

import os
import socket
import subprocess
from typing import Final

HOST: Final[str] = "0.0.0.0"
PORT: Final[int] = 5000
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
TERMINAL_SCRIPT = os.path.join(PROJECT_ROOT, "user_connect_terminal.py")


def launch_terminal_for_user(user_id: str) -> str:
    # Raspberry Pi desktop session required.
    command = [
        "lxterminal",
        "-e",
        f'python3 "{TERMINAL_SCRIPT}" "{user_id}"',
    ]
    subprocess.Popen(command)
    return "OK"


def handle_command(command: str) -> str:
    command = command.strip()

    if command.startswith("START_USER_CONNECT:"):
        user_id = command.split(":", 1)[1].strip() or "User"
        return launch_terminal_for_user(user_id)

    return "UNKNOWN_COMMAND"


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Pi TCP server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server.accept()
            with conn:
                data = conn.recv(1024).decode("utf-8", errors="ignore")
                reply = handle_command(data)
                conn.sendall((reply + "\n").encode("utf-8"))
                print(f"Handled {data.strip()} from {addr}: {reply}")


if __name__ == "__main__":
    main()
