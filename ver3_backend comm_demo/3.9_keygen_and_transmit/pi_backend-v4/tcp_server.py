from __future__ import annotations

import base64
import secrets
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Final


HOST: Final[str] = "0.0.0.0"
PORT: Final[int] = 5000

PROJECT_ROOT = Path(__file__).resolve().parent
MLDSA_DIR = PROJECT_ROOT / "mldsa_crypto"
KEY_STORE_DIR = MLDSA_DIR / "generated_keys"

AUTH_BINARY = MLDSA_DIR / "mldsa_auth"
KEYGEN_BINARY = MLDSA_DIR / "mldsa_keygen"


def log_backend_info(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [BACKEND INFO] {message}", flush=True)


def log_backend_error(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [BACKEND ERROR] {message}", flush=True)


def sanitize_user_id(user_id: str) -> str:
    cleaned = "".join(ch if (ch.isalnum() or ch in ("-", "_")) else "_" for ch in user_id.strip())
    return cleaned or "User"


def run_checked(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


def regenerate_public_key(user_id: str) -> str:
    log_backend_info(f"공개키 재발급 요청 수신 - user={user_id}")

    if not KEYGEN_BINARY.exists():
        log_backend_error(f"ML-DSA 키생성 바이너리를 찾을 수 없습니다. ({KEYGEN_BINARY})")
        return "ERROR: REGENERATE_FAILED"

    safe_user = sanitize_user_id(user_id)
    user_dir = KEY_STORE_DIR / safe_user
    user_dir.mkdir(parents=True, exist_ok=True)

    seed_file = user_dir / "seed.hex"
    private_key_path = user_dir / "mldsa_private.pem"
    public_key_path = user_dir / "mldsa_public.pem"

    seed_hex = secrets.token_hex(32)
    seed_file.write_text(seed_hex + "\n", encoding="utf-8")

    result = run_checked(
        [
            str(KEYGEN_BINARY),
            str(seed_file),
            str(private_key_path),
            str(public_key_path),
        ],
        MLDSA_DIR,
    )

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "세부 로그 없음"
        log_backend_error(f"ML-DSA 키쌍 생성 실패 - user={user_id}, detail={detail}")
        return "ERROR: REGENERATE_FAILED"

    if not public_key_path.exists():
        log_backend_error(f"생성된 공개키 파일을 찾을 수 없습니다. expected={public_key_path}")
        return "ERROR: REGENERATE_FAILED"

    public_key_pem = public_key_path.read_text(encoding="utf-8").strip()
    if not public_key_pem:
        log_backend_error(f"공개키 파일이 비어 있습니다. path={public_key_path}")
        return "ERROR: REGENERATE_FAILED"

    log_backend_info(f"공개키 재발급 완료 - user={user_id}, public_key={public_key_path}")

    public_key_b64 = base64.b64encode(public_key_pem.encode("utf-8")).decode("ascii")
    return f"PUBKEY_BASE64:{public_key_b64}"


def authenticate_user(user_id: str, phone_public_key_pem: str) -> str:
    log_backend_info(f"HSM 접속(ML-DSA 인증) 요청 수신 - user={user_id}")

    if not AUTH_BINARY.exists():
        log_backend_error(f"ML-DSA 인증 바이너리를 찾을 수 없습니다. ({AUTH_BINARY})")
        return "ERROR: AUTH_FAILED"

    safe_user = sanitize_user_id(user_id)
    user_dir = KEY_STORE_DIR / safe_user
    private_key_path = user_dir / "mldsa_private.pem"
    generated_public_key_path = user_dir / "mldsa_public.pem"
    phone_pubkey_path = user_dir / "phone_public_from_app.pem"

    if not private_key_path.exists():
        log_backend_error(f"사용자 개인키 파일이 없습니다. expected={private_key_path}")
        return "ERROR: AUTH_FAILED"

    if not generated_public_key_path.exists():
        log_backend_error(f"서버 생성 공개키 파일이 없습니다. expected={generated_public_key_path}")
        return "ERROR: AUTH_FAILED"

    normalized_phone_pub = phone_public_key_pem.replace("\r\n", "\n").strip() + "\n"
    generated_pub = generated_public_key_path.read_text(encoding="utf-8").replace("\r\n", "\n").strip() + "\n"

    log_backend_info(f"app pubkey size={len(normalized_phone_pub)}")
    log_backend_info(f"server pubkey size={len(generated_pub)}")
    log_backend_info(f"app pubkey begin={normalized_phone_pub.startswith('-----BEGIN PUBLIC KEY-----')}")
    log_backend_info(f"app pubkey end={normalized_phone_pub.strip().endswith('-----END PUBLIC KEY-----')}")
    log_backend_info(f"server/app pubkey match={generated_pub == normalized_phone_pub}")

    try:
        phone_pubkey_path.write_text(normalized_phone_pub, encoding="utf-8")
    except Exception as exc:
        log_backend_error(f"스마트폰 공개키 파일 저장 실패 - user={user_id}, detail={exc}")
        return "ERROR: AUTH_FAILED"

    if generated_pub != normalized_phone_pub:
        log_backend_error("스마트폰 공개키와 Pi 저장 공개키가 서로 다릅니다.")
        return "ERROR: AUTH_FAILED"

    result = run_checked(
        [
            str(AUTH_BINARY),
            str(private_key_path),
            str(phone_pubkey_path),
        ],
        MLDSA_DIR,
    )

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "세부 로그 없음"
        log_backend_error(f"ML-DSA 인증 실패 - user={user_id}, detail={detail}")
        return "ERROR: AUTH_FAILED"

    log_backend_info(f"HSM 접속(ML-DSA 인증) 성공 - user={user_id}")
    return "OK"

def recv_until_newline(conn: socket.socket) -> str:
    chunks: list[bytes] = []
    while True:
        packet = conn.recv(4096)
        if not packet:
            break
        chunks.append(packet)
        if b"\n" in packet:
            break

    return b"".join(chunks).decode("utf-8", errors="ignore").strip()


def handle_command(command: str) -> str:
    command = command.strip()

    if command.startswith("AUTH_USER_WITH_PUBKEY:"):
        parts = command.split(":", 2)
        if len(parts) != 3:
            log_backend_error(f"AUTH_USER_WITH_PUBKEY 명령 형식 오류: {command[:200]}")
            return "ERROR: INVALID_COMMAND"

        user_id = parts[1].strip() or "User"
        public_key_b64 = parts[2].strip()

        try:
            public_key_pem = base64.b64decode(public_key_b64).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"공개키 Base64 디코딩 실패 - user={user_id}, detail={exc}")
            return "ERROR: AUTH_FAILED"

        return authenticate_user(user_id, public_key_pem)

    if command.startswith("AUTH_USER:"):
        user_id = command.split(":", 1)[1].strip() or "User"
        log_backend_error(f"구형 AUTH_USER 명령은 더 이상 지원하지 않습니다. user={user_id}")
        return "ERROR: AUTH_FAILED"

    if command.startswith("REGENERATE_KEY:"):
        user_id = command.split(":", 1)[1].strip() or "User"
        return regenerate_public_key(user_id)

    log_backend_error(f"알 수 없는 명령을 수신했습니다: {command}")
    return "ERROR: UNKNOWN_COMMAND"


def main() -> None:
    KEY_STORE_DIR.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Pi TCP server listening on {HOST}:{PORT}", flush=True)

        while True:
            conn, addr = server.accept()
            with conn:
                log_backend_info(f"클라이언트 접속 - addr={addr[0]}:{addr[1]}")
                data = recv_until_newline(conn)
                log_backend_info(f"명령 수신 - addr={addr[0]}:{addr[1]}, command={data[:200]}")

                reply = handle_command(data)
                conn.sendall((reply + "\n").encode("utf-8"))


if __name__ == "__main__":
    main()