from __future__ import annotations

import base64
import secrets
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final


HOST: Final[str] = "0.0.0.0"
PORT: Final[int] = 5000
SESSION_TTL_SECONDS: Final[int] = 120

PROJECT_ROOT = Path(__file__).resolve().parent
MLDSA_DIR = PROJECT_ROOT / "mldsa_crypto"
KEY_STORE_DIR = MLDSA_DIR / "generated_keys"

AUTH_BINARY = MLDSA_DIR / "mldsa_auth"
KEYGEN_BINARY = MLDSA_DIR / "mldsa_keygen"


@dataclass
class PendingSession:
    user_id: str
    phone_public_key_pem: str
    client_challenge_b64: str
    server_challenge_b64: str
    expires_at: datetime


PENDING_SESSIONS: dict[str, PendingSession] = {}


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


def build_pi_auth_payload(user_id: str, session_id: str, client_challenge_b64: str, server_challenge_b64: str) -> bytes:
    return f"PI_AUTH|{user_id}|{session_id}|{client_challenge_b64}|{server_challenge_b64}".encode("utf-8")


def build_phone_auth_payload(user_id: str, session_id: str, client_challenge_b64: str, server_challenge_b64: str) -> bytes:
    return f"PHONE_AUTH|{user_id}|{session_id}|{client_challenge_b64}|{server_challenge_b64}".encode("utf-8")


def cleanup_expired_sessions() -> None:
    now = datetime.now()
    expired = [session_id for session_id, session in PENDING_SESSIONS.items() if session.expires_at <= now]
    for session_id in expired:
        del PENDING_SESSIONS[session_id]


def ensure_pi_keypair(user_id: str) -> tuple[Path, Path]:
    safe_user = sanitize_user_id(user_id)
    user_dir = KEY_STORE_DIR / safe_user
    user_dir.mkdir(parents=True, exist_ok=True)

    seed_file = user_dir / "pi_seed.hex"
    private_key_path = user_dir / "pi_mldsa_private.pem"
    public_key_path = user_dir / "pi_mldsa_public.pem"

    if private_key_path.exists() and public_key_path.exists():
        return private_key_path, public_key_path

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
        raise RuntimeError(f"Pi ML-DSA 키쌍 생성 실패: {detail}")

    return private_key_path, public_key_path


def ensure_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
    if not text:
        raise RuntimeError(f"파일이 비어 있습니다: {path}")
    return text + "\n"


def sign_with_private_key(private_key_path: Path, message_bytes: bytes) -> str:
    result = run_checked(
        [
            str(AUTH_BINARY),
            "sign",
            str(private_key_path),
            base64.b64encode(message_bytes).decode("ascii"),
        ],
        MLDSA_DIR,
    )

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "세부 로그 없음"
        raise RuntimeError(f"ML-DSA 서명 실패: {detail}")

    output = (result.stdout or "").strip()
    prefix = "SIG_BASE64:"
    if not output.startswith(prefix):
        raise RuntimeError(f"서명 결과 형식 오류: {output}")
    return output[len(prefix):]


def verify_with_public_key(public_key_path: Path, message_bytes: bytes, signature_b64: str) -> bool:
    result = run_checked(
        [
            str(AUTH_BINARY),
            "verify",
            str(public_key_path),
            base64.b64encode(message_bytes).decode("ascii"),
            signature_b64,
        ],
        MLDSA_DIR,
    )
    return result.returncode == 0 and (result.stdout or "").strip() == "OK"


def provision_device(user_id: str, phone_public_key_pem: str) -> str:
    log_backend_info(f"디바이스 등록 요청 수신 - user={user_id}")

    if not KEYGEN_BINARY.exists():
        log_backend_error(f"ML-DSA 키생성 바이너리를 찾을 수 없습니다. ({KEYGEN_BINARY})")
        return "ERROR: PROVISION_FAILED"

    try:
        _, pi_public_key_path = ensure_pi_keypair(user_id)
    except Exception as exc:
        log_backend_error(f"Pi 키쌍 준비 실패 - user={user_id}, detail={exc}")
        return "ERROR: PROVISION_FAILED"

    safe_user = sanitize_user_id(user_id)
    user_dir = KEY_STORE_DIR / safe_user
    phone_pubkey_path = user_dir / "phone_mldsa_public.pem"

    normalized_phone_pub = phone_public_key_pem.replace("\r\n", "\n").strip() + "\n"
    try:
        phone_pubkey_path.write_text(normalized_phone_pub, encoding="utf-8")
        pi_public_key_pem = ensure_text(pi_public_key_path)
    except Exception as exc:
        log_backend_error(f"디바이스 등록 저장 실패 - user={user_id}, detail={exc}")
        return "ERROR: PROVISION_FAILED"

    log_backend_info(f"디바이스 등록 완료 - user={user_id}, pi_public_key={pi_public_key_path}")
    return "PROVISION_OK:{pi_pub}".format(
        pi_pub=base64.b64encode(pi_public_key_pem.encode("utf-8")).decode("ascii")
    )


def start_mutual_auth(user_id: str, client_challenge_b64: str) -> str:
    cleanup_expired_sessions()
    log_backend_info(f"상호인증 시작 요청 수신 - user={user_id}")

    if not AUTH_BINARY.exists():
        log_backend_error(f"ML-DSA 인증 바이너리를 찾을 수 없습니다. ({AUTH_BINARY})")
        return "ERROR: AUTH_FAILED"

    safe_user = sanitize_user_id(user_id)
    user_dir = KEY_STORE_DIR / safe_user
    phone_pubkey_path = user_dir / "phone_mldsa_public.pem"

    if not phone_pubkey_path.exists():
        log_backend_error(f"등록된 스마트폰 공개키가 없습니다. expected={phone_pubkey_path}")
        return "ERROR: AUTH_FAILED"

    try:
        pi_private_key_path, pi_public_key_path = ensure_pi_keypair(user_id)
        phone_public_key_pem = ensure_text(phone_pubkey_path)
        pi_public_key_pem = ensure_text(pi_public_key_path)
        base64.b64decode(client_challenge_b64, validate=True)
    except Exception as exc:
        log_backend_error(f"상호인증 준비 실패 - user={user_id}, detail={exc}")
        return "ERROR: AUTH_FAILED"

    session_id = secrets.token_hex(16)
    server_challenge = secrets.token_bytes(32)
    server_challenge_b64 = base64.b64encode(server_challenge).decode("ascii")
    pi_payload = build_pi_auth_payload(user_id, session_id, client_challenge_b64, server_challenge_b64)

    try:
        pi_signature_b64 = sign_with_private_key(pi_private_key_path, pi_payload)
    except Exception as exc:
        log_backend_error(f"Pi 서명 실패 - user={user_id}, detail={exc}")
        return "ERROR: AUTH_FAILED"

    PENDING_SESSIONS[session_id] = PendingSession(
        user_id=user_id,
        phone_public_key_pem=phone_public_key_pem,
        client_challenge_b64=client_challenge_b64,
        server_challenge_b64=server_challenge_b64,
        expires_at=datetime.now() + timedelta(seconds=SESSION_TTL_SECONDS),
    )

    log_backend_info(f"상호인증 시작 응답 전송 - user={user_id}, session={session_id}")
    return "AUTH_START_OK:{session}:{pi_pub}:{server_challenge}:{pi_sig}".format(
        session=session_id,
        pi_pub=base64.b64encode(pi_public_key_pem.encode("utf-8")).decode("ascii"),
        server_challenge=server_challenge_b64,
        pi_sig=pi_signature_b64,
    )


def finish_mutual_auth(user_id: str, session_id: str, phone_signature_b64: str) -> str:
    cleanup_expired_sessions()
    log_backend_info(f"상호인증 완료 요청 수신 - user={user_id}, session={session_id}")

    session = PENDING_SESSIONS.get(session_id)
    if not session:
        log_backend_error(f"상호인증 세션이 없거나 만료되었습니다. user={user_id}, session={session_id}")
        return "ERROR: AUTH_FAILED"

    if session.user_id != user_id:
        log_backend_error(f"세션 user 불일치 - session_user={session.user_id}, request_user={user_id}")
        PENDING_SESSIONS.pop(session_id, None)
        return "ERROR: AUTH_FAILED"

    safe_user = sanitize_user_id(user_id)
    user_dir = KEY_STORE_DIR / safe_user
    phone_pubkey_path = user_dir / "phone_mldsa_public.pem"

    try:
        phone_pubkey_path.write_text(session.phone_public_key_pem, encoding="utf-8")
        phone_payload = build_phone_auth_payload(
            user_id,
            session_id,
            session.client_challenge_b64,
            session.server_challenge_b64,
        )
        ok = verify_with_public_key(phone_pubkey_path, phone_payload, phone_signature_b64)
    except Exception as exc:
        log_backend_error(f"스마트폰 서명 검증 중 예외 - user={user_id}, detail={exc}")
        PENDING_SESSIONS.pop(session_id, None)
        return "ERROR: AUTH_FAILED"

    PENDING_SESSIONS.pop(session_id, None)

    if not ok:
        log_backend_error(f"스마트폰 서명 검증 실패 - user={user_id}, session={session_id}")
        return "ERROR: AUTH_FAILED"

    log_backend_info(f"상호인증 성공 - user={user_id}, session={session_id}")
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

    if command.startswith("PROVISION_DEVICE:"):
        parts = command.split(":", 2)
        if len(parts) != 3:
            log_backend_error(f"PROVISION_DEVICE 명령 형식 오류: {command[:200]}")
            return "ERROR: INVALID_COMMAND"

        user_id = parts[1].strip() or "User"
        phone_pub_b64 = parts[2].strip()
        try:
            phone_public_key_pem = base64.b64decode(phone_pub_b64).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"스마트폰 공개키 Base64 디코딩 실패 - user={user_id}, detail={exc}")
            return "ERROR: PROVISION_FAILED"
        return provision_device(user_id, phone_public_key_pem)

    if command.startswith("START_MUTUAL_AUTH:"):
        parts = command.split(":", 2)
        if len(parts) != 3:
            log_backend_error(f"START_MUTUAL_AUTH 명령 형식 오류: {command[:200]}")
            return "ERROR: INVALID_COMMAND"
        user_id = parts[1].strip() or "User"
        client_challenge_b64 = parts[2].strip()
        return start_mutual_auth(user_id, client_challenge_b64)

    if command.startswith("FINISH_MUTUAL_AUTH:"):
        parts = command.split(":", 3)
        if len(parts) != 4:
            log_backend_error(f"FINISH_MUTUAL_AUTH 명령 형식 오류: {command[:200]}")
            return "ERROR: INVALID_COMMAND"
        user_id = parts[1].strip() or "User"
        session_id = parts[2].strip()
        phone_signature_b64 = parts[3].strip()
        return finish_mutual_auth(user_id, session_id, phone_signature_b64)

    if command.startswith("AUTH_USER_WITH_PUBKEY:") or command.startswith("AUTH_USER:") or command.startswith("REGENERATE_KEY:"):
        log_backend_error(f"구형 명령은 더 이상 지원하지 않습니다: {command[:120]}")
        return "ERROR: UNKNOWN_COMMAND"

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
