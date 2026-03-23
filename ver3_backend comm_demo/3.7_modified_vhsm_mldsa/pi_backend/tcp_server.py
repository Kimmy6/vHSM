from __future__ import annotations

import base64
import os
import secrets
import socket
import subprocess
from pathlib import Path
from typing import Final

HOST: Final[str] = "0.0.0.0"
PORT: Final[int] = 5000
PROJECT_ROOT = Path(__file__).resolve().parent
MLDSA_DIR = PROJECT_ROOT / "mldsa_crypto"
KEY_STORE_DIR = MLDSA_DIR / "generated_keys"
AUTH_BINARY = MLDSA_DIR / "mldsa_auth"
KEYGEN_BINARY = MLDSA_DIR / "mldsa_keygen"


def sanitize_user_id(user_id: str) -> str:
    cleaned = "".join(ch for ch in user_id if ch.isalnum() or ch in ("-", "_"))
    return cleaned or "User"


def run_checked(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=str(cwd), capture_output=True, text=True, check=False)


def authenticate_user(user_id: str) -> str:
    if not AUTH_BINARY.exists():
        return f"ERROR: ML-DSA 인증 바이너리를 찾을 수 없습니다. ({AUTH_BINARY})"

    result = run_checked([str(AUTH_BINARY)], MLDSA_DIR)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return f"ERROR: ML-DSA 인증 실패 ({detail})"
    return "OK"


def regenerate_public_key(user_id: str) -> str:
    if not KEYGEN_BINARY.exists():
        return f"ERROR: ML-DSA 키생성 바이너리를 찾을 수 없습니다. ({KEYGEN_BINARY})"

    safe_user = sanitize_user_id(user_id)
    user_dir = KEY_STORE_DIR / safe_user
    user_dir.mkdir(parents=True, exist_ok=True)

    seed_hex = secrets.token_hex(32)
    seed_file = user_dir / "seed.hex"
    seed_file.write_text(seed_hex, encoding="utf-8")

    result = run_checked([str(KEYGEN_BINARY), str(seed_file)], user_dir)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        return f"ERROR: ML-DSA 키쌍 생성 실패 ({detail})"

    public_key_path = user_dir / "mldsa_public.pem"
    if not public_key_path.exists():
        return "ERROR: 생성된 공개키 파일을 찾을 수 없습니다."

    public_key_b64 = base64.b64encode(public_key_path.read_bytes()).decode("ascii")
    return f"PUBKEY_BASE64:{public_key_b64}"


def handle_command(command: str) -> str:
    command = command.strip()

    if command.startswith("AUTH_USER:"):
        user_id = command.split(":", 1)[1].strip() or "User"
        return authenticate_user(user_id)

    if command.startswith("REGENERATE_KEY:"):
        user_id = command.split(":", 1)[1].strip() or "User"
        return regenerate_public_key(user_id)

    return "ERROR: UNKNOWN_COMMAND"


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Pi TCP server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server.accept()
            with conn:
                data = conn.recv(4096).decode("utf-8", errors="ignore")
                reply = handle_command(data)
                conn.sendall((reply + "\n").encode("utf-8"))


if __name__ == "__main__":
    main()
