from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import ssl
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Final

try:
    import serial
except ImportError:
    serial = None


HOST: Final[str] = "0.0.0.0"
PORT: Final[int] = 5000
ARDUINO_SERIAL_PORT: Final[str] = os.environ.get("VHSM_ARDUINO_PORT", "/dev/ttyACM0")
ARDUINO_BAUDRATE: Final[int] = int(os.environ.get("VHSM_ARDUINO_BAUD", "115200"))
ARDUINO_TIMEOUT_SECONDS: Final[float] = float(os.environ.get("VHSM_ARDUINO_TIMEOUT", "2.0"))

PROJECT_ROOT  = Path(__file__).resolve().parent
MLDSA_DIR     = PROJECT_ROOT / "mldsa_crypto"
KEY_STORE_DIR = MLDSA_DIR / "generated_keys"

AUTH_BINARY   = MLDSA_DIR / "mldsa_auth"
KEYGEN_BINARY = MLDSA_DIR / "mldsa_keygen"

TLS_CERT_PATH = PROJECT_ROOT / "tls_cert.pem"
TLS_KEY_PATH  = PROJECT_ROOT / "tls_key.pem"

# 사용자 DB 경로
USERS_DB_PATH = PROJECT_ROOT / "users.json"

# scrypt 파라미터 (Pi 4 기준 ~0.1초)
SCRYPT_N       = 2 ** 14
SCRYPT_R       = 8
SCRYPT_P       = 1
SCRYPT_DKLEN   = 32
SCRYPT_SALT_LEN = 16


# ─── 로깅 ───────────────────────────────────────────────────────────────────

def log_backend_info(message: str) -> None:
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [BACKEND INFO] {message}", flush=True)

def log_backend_error(message: str) -> None:
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [BACKEND ERROR] {message}", flush=True)


# ─── TLS ────────────────────────────────────────────────────────────────────

def ensure_tls_cert() -> tuple[Path, Path]:
    if TLS_CERT_PATH.exists() and TLS_KEY_PATH.exists():
        return TLS_CERT_PATH, TLS_KEY_PATH
    log_backend_info("TLS 인증서가 없습니다. 새로 생성합니다.")
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:P-256",
         "-keyout", str(TLS_KEY_PATH), "-out", str(TLS_CERT_PATH),
         "-days", "3650", "-nodes", "-subj", "/CN=vHSM-Pi"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"TLS 인증서 생성 실패: {result.stderr.strip()}")
    log_backend_info(f"TLS 인증서 생성 완료: {TLS_CERT_PATH}")
    return TLS_CERT_PATH, TLS_KEY_PATH

def create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(str(TLS_CERT_PATH), str(TLS_KEY_PATH))
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ─── 유틸 ───────────────────────────────────────────────────────────────────

def sanitize_user_id(user_id: str) -> str:
    cleaned = "".join(ch if (ch.isalnum() or ch in ("-", "_")) else "_" for ch in user_id.strip())
    return cleaned or "User"

def run_checked(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=str(cwd), capture_output=True, text=True, check=False)

def ensure_pi_keypair(user_id: str) -> tuple[Path, Path]:
    safe_user = sanitize_user_id(user_id)
    user_dir  = KEY_STORE_DIR / safe_user
    user_dir.mkdir(parents=True, exist_ok=True)
    seed_file        = user_dir / "pi_seed.hex"
    private_key_path = user_dir / "pi_mldsa_private.pem"
    public_key_path  = user_dir / "pi_mldsa_public.pem"
    cert_key_path    = user_dir / "pi_mldsa_cert.pem"
    if private_key_path.exists() and public_key_path.exists():
        return private_key_path, public_key_path
    seed_hex = secrets.token_hex(32)
    seed_file.write_text(seed_hex + "\n", encoding="utf-8")
    result = run_checked(
        [str(KEYGEN_BINARY), str(seed_file), str(private_key_path),
         str(public_key_path), str(cert_key_path), safe_user], MLDSA_DIR,
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
        [str(AUTH_BINARY), "sign", str(private_key_path),
         base64.b64encode(message_bytes).decode("ascii")], MLDSA_DIR,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "세부 로그 없음"
        raise RuntimeError(f"ML-DSA 서명 실패: {detail}")
    output = (result.stdout or "").strip()
    prefix = "SIG_BASE64:"
    if not output.startswith(prefix):
        raise RuntimeError(f"서명 결과 형식 오류: {output}")
    return output[len(prefix):]

def build_pi_auth_payload(user_id: str, nonce_b64: str) -> bytes:
    return f"PI_AUTH|{user_id}|{nonce_b64}".encode("utf-8")


# ─── 사용자 DB (scrypt 해싱) ────────────────────────────────────────────────
#
# users.json 구조:
# {
#   "users": {
#     "alice": {
#       "password_hash": "scrypt$<salt_hex>$<hash_hex>",
#       "name": "Alice",
#       "email": "alice@example.com"
#     }
#   }
# }

def load_users() -> dict:
    if not USERS_DB_PATH.exists():
        return {"users": {}}
    try:
        with USERS_DB_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if "users" not in data:
            data["users"] = {}
        return data
    except Exception as exc:
        log_backend_error(f"users.json 읽기 실패: {exc}")
        return {"users": {}}

def save_users(data: dict) -> None:
    with USERS_DB_PATH.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def hash_password(password: str) -> str:
    """scrypt 해싱. 반환: "scrypt$<salt_hex>$<hash_hex>" """
    salt = os.urandom(SCRYPT_SALT_LEN)
    h = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                       n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    return f"scrypt${salt.hex()}${h.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """timing-safe 비교로 timing attack 방지."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 3 or parts[0] != "scrypt":
            return False
        salt     = bytes.fromhex(parts[1])
        expected = bytes.fromhex(parts[2])
        computed = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                                  n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
        return hmac.compare_digest(computed, expected)
    except Exception as exc:
        log_backend_error(f"verify_password 예외: {exc}")
        return False


# ─── 회원가입 ────────────────────────────────────────────────────────────────
# 커맨드: REGISTER:<user_id>:<pw_b64>:<name_b64>:<email_b64>
# 응답:   REGISTER_OK | ERROR: ALREADY_EXISTS | ERROR: REGISTER_FAILED

def register_user(user_id: str, password: str, name: str, email: str) -> str:
    safe_id = sanitize_user_id(user_id)
    log_backend_info(f"회원가입 요청 - user_id={safe_id}")
    data = load_users()
    if safe_id in data["users"]:
        log_backend_error(f"회원가입 실패 — 이미 존재하는 ID: {safe_id}")
        return "ERROR: ALREADY_EXISTS"
    try:
        data["users"][safe_id] = {
            "password_hash": hash_password(password),
            "name":  name.strip(),
            "email": email.strip(),
        }
        save_users(data)
    except Exception as exc:
        log_backend_error(f"회원가입 저장 실패: {exc}")
        return "ERROR: REGISTER_FAILED"
    log_backend_info(f"회원가입 완료 - user_id={safe_id}")
    return "REGISTER_OK"


# ─── 로그인 ──────────────────────────────────────────────────────────────────
# 커맨드: LOGIN:<user_id>:<pw_b64>
# 응답:   LOGIN_OK | ERROR: INVALID_CREDENTIALS

def login_user(user_id: str, password: str) -> str:
    safe_id = sanitize_user_id(user_id)
    log_backend_info(f"로그인 시도 - user_id={safe_id}")
    data = load_users()
    record = data["users"].get(safe_id)

    # 사용자 없어도 동일 연산 수행 → timing attack 방지
    dummy_hash = "scrypt$" + "00" * 16 + "$" + "00" * 32
    stored_hash = record["password_hash"] if record else dummy_hash
    is_valid = verify_password(password, stored_hash)

    if not record or not is_valid:
        log_backend_error(f"로그인 실패 — 잘못된 인증 정보: user_id={safe_id}")
        return "ERROR: INVALID_CREDENTIALS"

    log_backend_info(f"로그인 성공 - user_id={safe_id}")
    return "LOGIN_OK"


# ─── 아이디 찾기 ──────────────────────────────────────────────────────────────
# 커맨드: FIND_ID:<name_b64>
# 응답:   FIND_ID_OK:<user_id> | ERROR: NOT_FOUND

def find_user_id(name: str) -> str:
    log_backend_info(f"아이디 찾기 요청 - name={name}")
    data   = load_users()
    target = name.strip().lower()
    for uid, record in data["users"].items():
        if record.get("name", "").strip().lower() == target:
            log_backend_info(f"아이디 찾기 완료 - user_id={uid}")
            return f"FIND_ID_OK:{uid}"
    log_backend_error(f"아이디 찾기 실패 — 일치하는 이름 없음: {name}")
    return "ERROR: NOT_FOUND"


# ─── 비밀번호 찾기 (계정 확인) ───────────────────────────────────────────────
# 커맨드: FIND_PASSWORD:<user_id>:<name_b64>
# 응답:   FIND_PASSWORD_OK | ERROR: NOT_FOUND

def find_password_check(user_id: str, name: str) -> str:
    safe_id = sanitize_user_id(user_id)
    log_backend_info(f"비밀번호 찾기 요청 - user_id={safe_id}")
    data   = load_users()
    record = data["users"].get(safe_id)
    if not record:
        log_backend_error(f"비밀번호 찾기 실패 — 존재하지 않는 ID: {safe_id}")
        return "ERROR: NOT_FOUND"
    if record.get("name", "").strip().lower() != name.strip().lower():
        log_backend_error(f"비밀번호 찾기 실패 — 이름 불일치: user_id={safe_id}")
        return "ERROR: NOT_FOUND"
    log_backend_info(f"비밀번호 찾기 계정 확인 완료 - user_id={safe_id}")
    return "FIND_PASSWORD_OK"


# ─── 비밀번호 재설정 ──────────────────────────────────────────────────────────
# 커맨드: RESET_PASSWORD:<user_id>:<new_pw_b64>
# 응답:   RESET_PASSWORD_OK | ERROR: NOT_FOUND | ERROR: RESET_FAILED

def reset_password(user_id: str, new_password: str) -> str:
    safe_id = sanitize_user_id(user_id)
    log_backend_info(f"비밀번호 재설정 요청 - user_id={safe_id}")
    data = load_users()
    if safe_id not in data["users"]:
        log_backend_error(f"비밀번호 재설정 실패 — 존재하지 않는 ID: {safe_id}")
        return "ERROR: NOT_FOUND"
    try:
        data["users"][safe_id]["password_hash"] = hash_password(new_password)
        save_users(data)
    except Exception as exc:
        log_backend_error(f"비밀번호 재설정 저장 실패: {exc}")
        return "ERROR: RESET_FAILED"
    log_backend_info(f"비밀번호 재설정 완료 - user_id={safe_id}")
    return "RESET_PASSWORD_OK"


# ─── 기존 커맨드 핸들러 ──────────────────────────────────────────────────────

def provision_device(user_id: str, phone_public_key_pem: str) -> str:
    log_backend_info(f"디바이스 등록 요청 수신 - user={user_id}")
    if not KEYGEN_BINARY.exists():
        log_backend_error(f"ML-DSA 키생성 바이너리를 찾을 수 없습니다. ({KEYGEN_BINARY})")
        return "ERROR: PROVISION_FAILED"
    try:
        _, pi_public_key_path = ensure_pi_keypair(user_id)
        pi_public_key_pem     = ensure_text(pi_public_key_path)
        tls_cert_pem          = TLS_CERT_PATH.read_text(encoding="utf-8")
    except Exception as exc:
        log_backend_error(f"Pi 키쌍 준비 실패 - user={user_id}, detail={exc}")
        return "ERROR: PROVISION_FAILED"
    log_backend_info(f"디바이스 등록 완료 - user={user_id}")
    return "PROVISION_OK:{pi_pub}:{tls_cert}".format(
        pi_pub   = base64.b64encode(pi_public_key_pem.encode("utf-8")).decode("ascii"),
        tls_cert = base64.b64encode(tls_cert_pem.encode("utf-8")).decode("ascii"),
    )

def start_auth(user_id: str, nonce_b64: str) -> str:
    log_backend_info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log_backend_info(f"[STEP 1/5] Challenge-Response 인증 시작 - user={user_id}")
    if not AUTH_BINARY.exists():
        log_backend_error(f"ML-DSA 인증 바이너리를 찾을 수 없습니다. ({AUTH_BINARY})")
        return "ERROR: AUTH_FAILED"
    try:
        nonce_bytes = base64.b64decode(nonce_b64, validate=True)
    except Exception as exc:
        log_backend_error(f"nonce Base64 디코딩 실패 - user={user_id}, detail={exc}")
        return "ERROR: AUTH_FAILED"
    nonce_preview = nonce_bytes.hex()[:16] + "..."
    log_backend_info(f"[STEP 2/5] Challenge 수신 - user={user_id}, nonce_preview=0x{nonce_preview}")
    try:
        pi_private_key_path, pi_public_key_path = ensure_pi_keypair(user_id)
    except Exception as exc:
        log_backend_error(f"Pi 키쌍 로드 실패 - user={user_id}, detail={exc}")
        return "ERROR: AUTH_FAILED"
    pi_payload = build_pi_auth_payload(user_id, nonce_b64)
    log_backend_info(f"[STEP 3/5] 서명 페이로드 구성 - payload_len={len(pi_payload)}bytes")
    try:
        pi_signature_b64 = sign_with_private_key(pi_private_key_path, pi_payload)
    except Exception as exc:
        log_backend_error(f"Pi 서명 실패 - user={user_id}, detail={exc}")
        return "ERROR: AUTH_FAILED"
    sig_bytes = base64.b64decode(pi_signature_b64)
    # 앱 ConnectPage preview 와 동일한 포맷: 4자씩 공백 구분
    sig_hex_raw    = sig_bytes[:16].hex().upper()
    sig_hex_spaced = " ".join(sig_hex_raw[i:i+4] for i in range(0, len(sig_hex_raw), 4))
    log_backend_info(f"[STEP 4/5] 서명 생성 완료 - sig_len={len(sig_bytes)}bytes")
    log_backend_info(f"[STEP 4/5] Pi 서명 앞 16bytes → 0x {sig_hex_spaced} ...")
    log_backend_info(f"[STEP 4/5] ↑ 앱 화면의 'Pi → 앱 수신 서명' 값과 비교하세요")
    log_backend_info(f"[STEP 5/5] 서명값 전송 - user={user_id}")
    log_backend_info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return f"AUTH_OK:{pi_signature_b64}"

def send_key_command_to_arduino(mode: str, key_number: str) -> tuple[bool, str]:
    if serial is None:
        return False, "pyserial이 설치되지 않았습니다. 'pip install pyserial' 후 다시 시도해주세요."
    payload = f"KEY:{mode}:{key_number}\n".encode("utf-8")
    try:
        with serial.Serial(ARDUINO_SERIAL_PORT, ARDUINO_BAUDRATE, timeout=ARDUINO_TIMEOUT_SECONDS) as ser:
            time.sleep(2.0)
            ser.reset_input_buffer()
            ser.reset_output_buffer()
            ser.write(payload)
            ser.flush()
            response = ser.readline().decode("utf-8", errors="ignore").strip()
    except Exception as exc:
        return False, f"Arduino 시리얼 통신 실패 ({ARDUINO_SERIAL_PORT}): {exc}"
    if not response:
        return False, "Arduino 응답이 없습니다."
    return (True, response) if response == "OK" else (False, response)

def handle_key_command(user_id: str, mode: str, key_number: str) -> str:
    log_backend_info(f"키 명령 수신 - user={user_id}, mode={mode}, key={key_number}")
    normalized_mode = mode.strip().lower()
    normalized_key  = key_number.strip()
    if normalized_mode not in {"encrypt", "decrypt"}:
        return "ERROR: INVALID_MODE"
    if normalized_key not in {"1", "2", "3"}:
        return "ERROR: INVALID_KEY"
    ok, detail = send_key_command_to_arduino(normalized_mode, normalized_key)
    if not ok:
        log_backend_error(f"Arduino 키 명령 실패 - detail={detail}")
        return f"ERROR: {detail}"
    pin_label = {"1": "D3", "2": "D4", "3": "D5"}[normalized_key]
    log_backend_info(f"Arduino 키 명령 완료 - key={normalized_key}, pin={pin_label}")
    return "KEY_OK"


# ─── 메인 커맨드 디스패처 ────────────────────────────────────────────────────

def handle_command(command: str) -> str:
    command = command.strip()

    # 기존 커맨드
    if command.startswith("PROVISION_DEVICE:"):
        parts = command.split(":", 2)
        if len(parts) != 3:
            return "ERROR: INVALID_COMMAND"
        user_id = parts[1].strip() or "User"
        try:
            phone_public_key_pem = base64.b64decode(parts[2].strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"PROVISION 디코딩 실패: {exc}")
            return "ERROR: PROVISION_FAILED"
        return provision_device(user_id, phone_public_key_pem)

    if command.startswith("START_AUTH:"):
        parts = command.split(":", 2)
        if len(parts) != 3:
            return "ERROR: INVALID_COMMAND"
        return start_auth(parts[1].strip() or "User", parts[2].strip())

    if command.startswith("KEY_COMMAND:"):
        parts = command.split(":", 3)
        if len(parts) != 4:
            return "ERROR: INVALID_COMMAND"
        return handle_key_command(parts[1].strip() or "User", parts[2].strip(), parts[3].strip())

    # 신규: ID/PW 인증 커맨드
    if command.startswith("REGISTER:"):
        # REGISTER:<user_id>:<pw_b64>:<name_b64>:<email_b64>
        parts = command.split(":", 4)
        if len(parts) != 5:
            return "ERROR: INVALID_COMMAND"
        try:
            password = base64.b64decode(parts[2].strip()).decode("utf-8")
            name     = base64.b64decode(parts[3].strip()).decode("utf-8")
            email    = base64.b64decode(parts[4].strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"REGISTER 디코딩 실패: {exc}")
            return "ERROR: REGISTER_FAILED"
        return register_user(parts[1].strip(), password, name, email)

    if command.startswith("LOGIN:"):
        # LOGIN:<user_id>:<pw_b64>
        parts = command.split(":", 2)
        if len(parts) != 3:
            return "ERROR: INVALID_COMMAND"
        try:
            password = base64.b64decode(parts[2].strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"LOGIN 디코딩 실패: {exc}")
            return "ERROR: AUTH_FAILED"
        return login_user(parts[1].strip(), password)

    if command.startswith("FIND_ID:"):
        # FIND_ID:<name_b64>
        rest = command[len("FIND_ID:"):]
        try:
            name = base64.b64decode(rest.strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"FIND_ID 디코딩 실패: {exc}")
            return "ERROR: NOT_FOUND"
        return find_user_id(name)

    if command.startswith("FIND_PASSWORD:"):
        # FIND_PASSWORD:<user_id>:<name_b64>
        parts = command.split(":", 2)
        if len(parts) != 3:
            return "ERROR: INVALID_COMMAND"
        try:
            name = base64.b64decode(parts[2].strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"FIND_PASSWORD 디코딩 실패: {exc}")
            return "ERROR: NOT_FOUND"
        return find_password_check(parts[1].strip(), name)

    if command.startswith("RESET_PASSWORD:"):
        # RESET_PASSWORD:<user_id>:<new_pw_b64>
        parts = command.split(":", 2)
        if len(parts) != 3:
            return "ERROR: INVALID_COMMAND"
        try:
            new_password = base64.b64decode(parts[2].strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"RESET_PASSWORD 디코딩 실패: {exc}")
            return "ERROR: RESET_FAILED"
        return reset_password(parts[1].strip(), new_password)

    # SESSION_CLOSE는 main 루프에서 처리되지만 혹시 여기 오면 안내
    if command.startswith("SESSION_CLOSE:"):
        return "SESSION_CLOSED"

    log_backend_error(f"알 수 없는 명령: {command[:120]}")
    return "ERROR: UNKNOWN_COMMAND"


# ─── 소켓 수신 ───────────────────────────────────────────────────────────────

def recv_until_newline(conn: ssl.SSLSocket) -> str:
    chunks: list[bytes] = []
    while True:
        packet = conn.recv(4096)
        if not packet:
            break
        chunks.append(packet)
        if b"\n" in packet:
            break
    return b"".join(chunks).decode("utf-8", errors="ignore").strip()


# ─── 메인 루프 ───────────────────────────────────────────────────────────────

def main() -> None:
    KEY_STORE_DIR.mkdir(parents=True, exist_ok=True)
    ensure_tls_cert()
    ssl_ctx = create_ssl_context()
    log_backend_info(f"TLS 1.3 서버 준비 완료 (cert={TLS_CERT_PATH})")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        log_backend_info(f"Pi TLS 1.3 server listening on {HOST}:{PORT}")

        while True:
            raw_conn, addr = server.accept()
            client_ip, client_port = addr[0], addr[1]
            log_backend_info(f"접속 시도 감지 - client={client_ip}:{client_port}")
            try:
                conn = ssl_ctx.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as exc:
                log_backend_error(f"TLS 핸드셰이크 실패 - client={client_ip}:{client_port}, detail={exc}")
                raw_conn.close()
                continue

            log_backend_info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            log_backend_info(f"[TLS 세션 시작] client={client_ip}:{client_port}")
            with conn:
                session_user: str = ""
                try:
                    # ── 첫 번째 커맨드 처리 ──────────────────────────────────
                    data = recv_until_newline(conn)
                    if not data:
                        log_backend_info(f"[TLS 세션 종료] 빈 요청 - client={client_ip}:{client_port}")
                        log_backend_info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                        continue

                    log_backend_info(f"명령 수신 - command={data[:200]}")
                    reply = handle_command(data)
                    log_backend_info(f"응답 전송 - reply={reply[:120]}")
                    conn.sendall((reply + "\n").encode("utf-8"))

                    # ── START_AUTH 성공 → persistent 세션 루프 진입 ──────────
                    if data.startswith("START_AUTH:") and reply.startswith("AUTH_OK:"):
                        parts = data.split(":", 2)
                        session_user = parts[1].strip() if len(parts) > 1 else "unknown"
                        log_backend_info(f"[세션 유지] 인증 완료 - user={session_user}, client={client_ip}:{client_port}")

                        while True:
                            cmd = recv_until_newline(conn)

                            # 빈 수신 = 클라이언트가 소켓을 그냥 닫음 (앱 강제 종료 등)
                            if not cmd:
                                log_backend_info(
                                    f"[세션 종료] 클라이언트 연결 끊김 (비정상) "
                                    f"- user={session_user}, client={client_ip}:{client_port}"
                                )
                                break

                            # 정상 종료 요청
                            if cmd.startswith("SESSION_CLOSE:"):
                                uid = cmd.split(":", 1)[1].strip() if ":" in cmd else session_user
                                log_backend_info(
                                    f"[세션 종료] 정상 종료 요청 수신 "
                                    f"- user={uid}, client={client_ip}:{client_port}"
                                )
                                conn.sendall(b"SESSION_CLOSED\n")
                                break

                            log_backend_info(f"[세션 명령] user={session_user}, command={cmd[:200]}")
                            resp = handle_command(cmd)
                            log_backend_info(f"[세션 응답] reply={resp[:120]}")
                            conn.sendall((resp + "\n").encode("utf-8"))

                except Exception as exc:
                    log_backend_error(f"클라이언트 처리 중 예외 - detail={exc}")
                    try:
                        conn.sendall(b"ERROR: INTERNAL_SERVER_ERROR\n")
                    except Exception:
                        pass

            if session_user:
                log_backend_info(f"[TLS 세션 종료] user={session_user}, client={client_ip}:{client_port}")
            else:
                log_backend_info(f"[TLS 세션 종료] client={client_ip}:{client_port}")
            log_backend_info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


if __name__ == "__main__":
    main()
