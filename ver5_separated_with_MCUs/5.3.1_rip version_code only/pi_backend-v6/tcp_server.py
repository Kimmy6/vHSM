from __future__ import annotations

import base64
import fcntl
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
import termios

# ── [변경] Arduino serial → RPi.GPIO ─────────────────────────────────────
try:
    import RPi.GPIO as GPIO
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    _LED_PINS = {1: 17, 2: 27, 3: 22}
    for _pin in _LED_PINS.values():
        GPIO.setup(_pin, GPIO.OUT, initial=GPIO.LOW)
except Exception:
    GPIO = None

ESP32_PORT    = "/dev/ttyAMA0"
ESP32_BAUD    = 115200
ESP32_TIMEOUT = 30
# ─────────────────────────────────────────────────────────────────────────────

HOST: Final[str] = "0.0.0.0"
PORT: Final[int] = 5000

PROJECT_ROOT  = Path(__file__).resolve().parent
MLDSA_DIR     = PROJECT_ROOT / "mldsa_crypto"
KEY_STORE_DIR = MLDSA_DIR / "generated_keys"

AUTH_BINARY   = MLDSA_DIR / "mldsa_auth"
KEYGEN_BINARY = MLDSA_DIR / "mldsa_keygen"

TLS_CERT_PATH = PROJECT_ROOT / "tls_cert.pem"
TLS_KEY_PATH  = PROJECT_ROOT / "tls_key.pem"
CA_CERT_PATH  = PROJECT_ROOT / "ca_cert.pem"
CA_KEY_PATH   = PROJECT_ROOT / "ca_key.pem"

USERS_DB_PATH = PROJECT_ROOT / "users.json"
AUDIT_LOG_PATH = PROJECT_ROOT / "audit.log"

SCRYPT_N        = 2 ** 14
SCRYPT_R        = 8
SCRYPT_P        = 1
SCRYPT_DKLEN    = 32
SCRYPT_SALT_LEN = 16

KEY_BYTES = 24  # AES-192 = 24 bytes

# ─── 로깅 ───────────────────────────────────────────────────────────────────

def log_backend_info(message: str) -> None:
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [BACKEND INFO] {message}", flush=True)

def log_backend_error(message: str) -> None:
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [BACKEND ERROR] {message}", flush=True)

def log_audit(event: str, user_id: str = "", role: str = "", detail: str = "", client_ip: str = "") -> None:
    entry = json.dumps({
        "timestamp": datetime.utcnow().isoformat(),
        "event":     event,
        "user":      user_id,
        "role":      role,
        "detail":    detail,
        "client_ip": client_ip,
    }, ensure_ascii=False)
    try:
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception as exc:
        log_backend_error(f"감사 로그 기록 실패: {exc}")


# ─── TLS ────────────────────────────────────────────────────────────────────

def ensure_tls_cert() -> tuple[Path, Path]:
    if TLS_CERT_PATH.exists() and TLS_KEY_PATH.exists() and CA_CERT_PATH.exists():
        return TLS_CERT_PATH, TLS_KEY_PATH

    log_backend_info("TLS 인증서가 없습니다. Private CA + 서버 인증서를 새로 생성합니다.")

    # Step 1: Private CA 생성
    if not CA_CERT_PATH.exists() or not CA_KEY_PATH.exists():
        r = subprocess.run(
            ["openssl", "genrsa", "-out", str(CA_KEY_PATH), "2048"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"CA 키 생성 실패: {r.stderr.strip()}")

        r = subprocess.run(
            ["openssl", "req", "-x509", "-new", "-nodes",
             "-key", str(CA_KEY_PATH), "-out", str(CA_CERT_PATH),
             "-days", "3650", "-subj", "/CN=vHSM-Private-CA"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"CA 인증서 생성 실패: {r.stderr.strip()}")
        log_backend_info(f"Private CA 생성 완료: {CA_CERT_PATH}")

    # Step 2: 서버 키 생성
    r = subprocess.run(
        ["openssl", "ecparam", "-genkey", "-name", "P-256",
         "-noout", "-out", str(TLS_KEY_PATH)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"서버 키 생성 실패: {r.stderr.strip()}")

    # Step 3: CSR 생성
    csr_path = PROJECT_ROOT / "server.csr"
    r = subprocess.run(
        ["openssl", "req", "-new", "-key", str(TLS_KEY_PATH),
         "-out", str(csr_path), "-subj", "/CN=vHSM-Pi"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"CSR 생성 실패: {r.stderr.strip()}")

    # Step 4: CA로 서버 인증서 서명
    r = subprocess.run(
        ["openssl", "x509", "-req",
         "-in", str(csr_path),
         "-CA", str(CA_CERT_PATH), "-CAkey", str(CA_KEY_PATH),
         "-CAcreateserial", "-out", str(TLS_CERT_PATH),
         "-days", "3650"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"서버 인증서 서명 실패: {r.stderr.strip()}")

    csr_path.unlink(missing_ok=True)
    log_backend_info(f"CA 서명 TLS 인증서 생성 완료: {TLS_CERT_PATH}")
    log_backend_info(f"[중요] Android 앱에 번들할 CA 인증서: {CA_CERT_PATH}")
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


# ─── 역할 / 권한 정의 ────────────────────────────────────────────────────────

VALID_ROLES: Final[set] = {
    "public_user",
    "audit_user",
    "partition_security_officer",
    "puf_maintenance_officer",
    "hsm_root_officer",
}

ROLE_PERMISSIONS: Final[dict] = {
    "public_user":                {"KEY_COMMAND", "LOGIN", "START_AUTH"},
    "audit_user":                 {"LOGIN", "START_AUTH", "GET_AUDIT_LOG"},
    "partition_security_officer": {"LOGIN", "START_AUTH", "PARTITION_POLICY"},
    "puf_maintenance_officer":    {"LOGIN", "START_AUTH", "ZEROIZE_PUF"},
    "hsm_root_officer":           {"LOGIN", "START_AUTH", "GET_AUDIT_LOG", "KEY_COMMAND",
                                   "PARTITION_POLICY", "ZEROIZE_PUF", "ZEROIZE_ALL",
                                   "CREATE_SLOT", "CREATE_USER", "LIST_SLOTS"},
}

# ─── 슬롯 기반 DB ────────────────────────────────────────────────────────────
# users.json 구조:
# {
#   "root_officers": { "<id>": { "password_hash", "name", "email", "role" } },
#   "slots": {
#     "<slot_id>": {
#       "name": "...", "created_by": "<root_id>",
#       "users": { "<id>": { "password_hash", "name", "email", "role" } }
#     }
#   }
# }

def _empty_db() -> dict:
    return {"root_officers": {}, "slots": {}, "invite_codes": {}}

def load_users() -> dict:
    if not USERS_DB_PATH.exists():
        return _empty_db()
    try:
        with USERS_DB_PATH.open("r", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_SH)
            try:
                data = json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        if "root_officers" not in data:
            return _empty_db()
        if "slots" not in data:
            data["slots"] = {}
        if "invite_codes" not in data:
            data["invite_codes"] = {}
        return data
    except Exception as exc:
        log_backend_error(f"users.json 읽기 실패: {exc}")
        return _empty_db()

def save_users(data: dict) -> None:
    with USERS_DB_PATH.open("w", encoding="utf-8") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            json.dump(data, f, ensure_ascii=False, indent=2)
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)

def is_db_empty() -> bool:
    data = load_users()
    return len(data["root_officers"]) == 0

def _find_record(user_id: str) -> tuple:
    """(record | None, role_str) 반환. root_officers → slots 순 탐색."""
    safe = sanitize_user_id(user_id)
    data = load_users()
    if safe in data["root_officers"]:
        rec = data["root_officers"][safe]
        return rec, rec.get("role", "hsm_root_officer")
    for slot in data["slots"].values():
        if safe in slot.get("users", {}):
            rec = slot["users"][safe]
            return rec, rec.get("role", "public_user")
    return None, ""

def get_user_role(user_id: str) -> str:
    _, role = _find_record(user_id)
    return role or "public_user"

def is_allowed(user_id: str, command_prefix: str) -> bool:
    return command_prefix in ROLE_PERMISSIONS.get(get_user_role(user_id), set())

def hash_password(password: str) -> str:
    salt = os.urandom(SCRYPT_SALT_LEN)
    h = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                       n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    return f"scrypt${salt.hex()}${h.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
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


# ─── Bootstrap: 최초 Root Officer 등록 ───────────────────────────────────────

def bootstrap_root_officer(user_id: str, password: str, name: str, email: str) -> str:
    if not is_db_empty():
        log_backend_error("Bootstrap 거부 — DB가 이미 초기화되어 있습니다.")
        return "ERROR: BOOTSTRAP_NOT_ALLOWED"
    safe_id = sanitize_user_id(user_id)
    data = load_users()
    data["root_officers"][safe_id] = {
        "password_hash": hash_password(password),
        "name":  name.strip(),
        "email": email.strip(),
        "role":  "hsm_root_officer",
    }
    save_users(data)
    log_backend_info(f"Bootstrap 완료 — HSM Root Officer 생성: {safe_id}")
    return "BOOTSTRAP_OK"

# ─── 슬롯 생성 (Root Officer 전용) ───────────────────────────────────────────

def create_slot(root_id: str, slot_name: str, allowed_roles: list | None = None) -> str:
    if get_user_role(root_id) != "hsm_root_officer":
        return "ERROR: PERMISSION_DENIED"
    import uuid
    data = load_users()
    slot_id = "slot_" + uuid.uuid4().hex[:8]
    permitted = [r for r in (allowed_roles or []) if r in VALID_ROLES and r != "hsm_root_officer"]
    if not permitted:
        permitted = ["public_user", "audit_user", "partition_security_officer", "puf_maintenance_officer"]
    data["slots"][slot_id] = {
        "name":          slot_name.strip(),
        "created_by":    sanitize_user_id(root_id),
        "allowed_roles": permitted,
        "users":         {},
    }
    save_users(data)
    log_backend_info(f"슬롯 생성: {slot_id} ('{slot_name}') by {root_id}, allowed={permitted}")
    log_audit("CREATE_SLOT", user_id=root_id, role="hsm_root_officer",
              detail=f"slot_id={slot_id}, name={slot_name}, allowed_roles={permitted}")
    return f"CREATE_SLOT_OK:{slot_id}"

# ─── 슬롯 내 유저 생성 (Root Officer 전용) ────────────────────────────────────

def create_user_in_slot(root_id: str, slot_id: str, new_id: str,
                        password: str, name: str, email: str, role: str) -> str:
    if get_user_role(root_id) != "hsm_root_officer":
        return "ERROR: PERMISSION_DENIED"
    if role not in VALID_ROLES or role == "hsm_root_officer":
        return "ERROR: INVALID_ROLE"
    data = load_users()
    if slot_id not in data["slots"]:
        return "ERROR: SLOT_NOT_FOUND"
    allowed = data["slots"][slot_id].get("allowed_roles", [])
    if allowed and role not in allowed:
        return "ERROR: ROLE_NOT_ALLOWED_IN_SLOT"
    safe_new = sanitize_user_id(new_id)
    # 전체 DB에서 중복 ID 검사
    if safe_new in data["root_officers"]:
        return "ERROR: ALREADY_EXISTS"
    for slot in data["slots"].values():
        if safe_new in slot.get("users", {}):
            return "ERROR: ALREADY_EXISTS"
    data["slots"][slot_id]["users"][safe_new] = {
        "password_hash": hash_password(password),
        "name":  name.strip(),
        "email": email.strip(),
        "role":  role,
    }
    save_users(data)
    log_backend_info(f"유저 생성: {safe_new} ({role}) in {slot_id} by {root_id}")
    return "CREATE_USER_OK"

# ─── 슬롯 목록 조회 ──────────────────────────────────────────────────────────

def list_slots_cmd(root_id: str) -> str:
    if get_user_role(root_id) != "hsm_root_officer":
        return "ERROR: PERMISSION_DENIED"
    data = load_users()
    slots = [
        {
            "id":            sid,
            "name":          info["name"],
            "allowed_roles": info.get("allowed_roles", []),
            "user_count":    len(info.get("users", {})),
        }
        for sid, info in data["slots"].items()
    ]
    payload = base64.b64encode(json.dumps(slots, ensure_ascii=False).encode()).decode()
    return f"LIST_SLOTS_OK:{payload}"


# ─── 초대 코드 생성 (Root Officer 전용) ─────────────────────────────────────

def generate_invite(root_id: str, slot_id: str, role: str, expire_days: int) -> str:
    if get_user_role(root_id) != "hsm_root_officer":
        return "ERROR: PERMISSION_DENIED"
    if role not in VALID_ROLES or role == "hsm_root_officer":
        return "ERROR: INVALID_ROLE"
    data = load_users()
    if slot_id not in data["slots"]:
        return "ERROR: SLOT_NOT_FOUND"
    allowed = data["slots"][slot_id].get("allowed_roles", [])
    if allowed and role not in allowed:
        return "ERROR: ROLE_NOT_ALLOWED_IN_SLOT"
    import secrets, string as _string
    _ALPHABET = _string.ascii_uppercase + _string.digits
    while True:
        code = "".join(secrets.choice(_ALPHABET) for _ in range(6))
        if code not in data["invite_codes"]:
            break
    from datetime import datetime, timedelta
    expires_at = (datetime.utcnow() + timedelta(days=max(1, expire_days))).isoformat()
    data["invite_codes"][code] = {
        "slot_id":    slot_id,
        "role":       role,
        "created_by": sanitize_user_id(root_id),
        "expires_at": expires_at,
        "used":       False,
    }
    save_users(data)
    log_backend_info(f"초대 코드 생성: {code} (slot={slot_id}, role={role}, expires={expires_at})")
    log_audit("GENERATE_INVITE", user_id=root_id, role="hsm_root_officer",
              detail=f"code={code}, slot={slot_id}, role={role}")
    return f"INVITE_OK:{code}"

# ─── 초대 코드로 회원가입 ────────────────────────────────────────────────────

def register_with_invite(code: str, new_id: str,
                         password: str, name: str, email: str) -> str:
    from datetime import datetime
    data = load_users()
    invite = data["invite_codes"].get(code.upper().strip())
    if not invite:
        return "ERROR: INVALID_CODE"
    if invite["used"]:
        return "ERROR: CODE_ALREADY_USED"
    try:
        expires_at = datetime.fromisoformat(invite["expires_at"])
        if datetime.utcnow() > expires_at:
            return "ERROR: CODE_EXPIRED"
    except Exception:
        return "ERROR: INVALID_CODE"
    slot_id = invite["slot_id"]
    role    = invite["role"]
    if slot_id not in data["slots"]:
        return "ERROR: SLOT_NOT_FOUND"
    safe_new = sanitize_user_id(new_id)
    # 중복 ID 검사
    if safe_new in data["root_officers"]:
        return "ERROR: ALREADY_EXISTS"
    for slot in data["slots"].values():
        if safe_new in slot.get("users", {}):
            return "ERROR: ALREADY_EXISTS"
    data["slots"][slot_id]["users"][safe_new] = {
        "password_hash": hash_password(password),
        "name":  name.strip(),
        "email": email.strip(),
        "role":  role,
    }
    invite["used"] = True  # 코드 소멸 (1회용)
    save_users(data)
    log_backend_info(f"초대 코드 가입 완료: {safe_new} ({role}) in {slot_id}")
    log_audit("REGISTER", user_id=safe_new, role=role, detail=f"slot={slot_id}, code={code}")
    return "REGISTER_WITH_INVITE_OK"

# ─── 로그인 ──────────────────────────────────────────────────────────────────

def login_user(user_id: str, password: str) -> str:
    safe_id = sanitize_user_id(user_id)
    log_backend_info(f"로그인 시도 - user_id={safe_id}")
    record, role = _find_record(safe_id)
    dummy_hash = "scrypt$" + "00" * 16 + "$" + "00" * 32
    stored_hash = record["password_hash"] if record else dummy_hash
    is_valid = verify_password(password, stored_hash)
    if not record or not is_valid:
        log_backend_error(f"로그인 실패 — 잘못된 인증 정보: user_id={safe_id}")
        log_audit("LOGIN_FAIL", user_id=safe_id, detail="INVALID_CREDENTIALS")
        return "ERROR: INVALID_CREDENTIALS"
    # 앱 접근 불가 역할 — Pi CLI(hsm_cli.py) 전용
    _BACKEND_CLI_ONLY = {"hsm_root_officer", "puf_maintenance_officer", "partition_security_officer"}
    if role in _BACKEND_CLI_ONLY:
        log_backend_error(f"로그인 거부 — CLI 전용 역할: user_id={safe_id}, role={role}")
        log_audit("LOGIN_DENY", user_id=safe_id, role=role, detail="BACKEND_CLI_ONLY")
        return "ERROR: BACKEND_CLI_ONLY"
    log_backend_info(f"로그인 성공 - user_id={safe_id}, role={role}")
    log_audit("LOGIN_OK", user_id=safe_id, role=role)
    return f"LOGIN_OK:{role}"


# ─── 아이디 찾기 ──────────────────────────────────────────────────────────────

def find_user_id(name: str) -> str:
    log_backend_info(f"아이디 찾기 요청 - name={name}")
    data   = load_users()
    target = name.strip().lower()
    # root_officers 탐색
    for uid, record in data["root_officers"].items():
        if record.get("name", "").strip().lower() == target:
            return f"FIND_ID_OK:{uid}"
    # slots 탐색
    for slot in data["slots"].values():
        for uid, record in slot.get("users", {}).items():
            if record.get("name", "").strip().lower() == target:
                return f"FIND_ID_OK:{uid}"
    log_backend_error(f"아이디 찾기 실패 — 일치하는 이름 없음: {name}")
    return "ERROR: NOT_FOUND"


# ─── 비밀번호 찾기 ───────────────────────────────────────────────────────────

def find_password_check(user_id: str, name: str) -> str:
    safe_id = sanitize_user_id(user_id)
    log_backend_info(f"비밀번호 찾기 요청 - user_id={safe_id}")
    record, _ = _find_record(safe_id)
    if not record:
        log_backend_error(f"비밀번호 찾기 실패 — 존재하지 않는 ID: {safe_id}")
        return "ERROR: NOT_FOUND"
    if record.get("name", "").strip().lower() != name.strip().lower():
        log_backend_error(f"비밀번호 찾기 실패 — 이름 불일치: user_id={safe_id}")
        return "ERROR: NOT_FOUND"
    log_backend_info(f"비밀번호 찾기 계정 확인 완료 - user_id={safe_id}")
    return "FIND_PASSWORD_OK"


# ─── 비밀번호 재설정 ──────────────────────────────────────────────────────────

def reset_password(user_id: str, new_password: str) -> str:
    safe_id = sanitize_user_id(user_id)
    log_backend_info(f"비밀번호 재설정 요청 - user_id={safe_id}")
    data = load_users()
    # root_officers 탐색
    if safe_id in data["root_officers"]:
        data["root_officers"][safe_id]["password_hash"] = hash_password(new_password)
        save_users(data)
        return "RESET_PASSWORD_OK"
    # slots 탐색
    for slot in data["slots"].values():
        if safe_id in slot.get("users", {}):
            slot["users"][safe_id]["password_hash"] = hash_password(new_password)
            save_users(data)
            return "RESET_PASSWORD_OK"
    log_backend_error(f"비밀번호 재설정 실패 — 존재하지 않는 ID: {safe_id}")
    return "ERROR: NOT_FOUND"


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
    sig_hex_raw    = sig_bytes[:16].hex().upper()
    sig_hex_spaced = " ".join(sig_hex_raw[i:i+4] for i in range(0, len(sig_hex_raw), 4))
    log_backend_info(f"[STEP 4/5] 서명 생성 완료 - sig_len={len(sig_bytes)}bytes")
    log_backend_info(f"[STEP 4/5] Pi 서명 앞 16bytes → 0x {sig_hex_spaced} ...")
    log_backend_info(f"[STEP 4/5] ↑ 앱 화면의 'Pi → 앱 수신 서명' 값과 비교하세요")
    log_backend_info(f"[STEP 5/5] 서명값 전송 - user={user_id}")
    log_backend_info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return f"AUTH_OK:{pi_signature_b64}"


# ─── [변경] LED ON + ESP32 트리거 + 키 수신 ─────────────────────────────────

def activate_led_and_capture(key_number: str) -> "tuple[bool, str, bytes | None]":
    """LED ON → ESP32 트리거 → 키 수신 → LED OFF (pyserial 없이 직접 파일 I/O)"""
    key = int(key_number)
    pin = _LED_PINS.get(key)
    if pin is None:
        return False, f"유효하지 않은 key_number: {key_number}", None

    # pyserial 대신 stty로 설정 → 파일 직접 열기 (설정 덮어쓰기 없음)
    subprocess.run(
        ["stty", "-F", ESP32_PORT, "115200", "cs8", "-cstopb", "-parenb", "raw"],
        check=False
    )

    key_bytes = None
    fd = None
    try:
        fd = os.open(ESP32_PORT, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        os.set_blocking(fd, True)  # open 후 다시 blocking으로

        termios.tcflush(fd, termios.TCIOFLUSH)
        time.sleep(0.1)

        def _readline(timeout_sec: float) -> "str | None":
            """fd에서 \n 까지 한 줄 읽기. 타임아웃 초과 시 None 반환"""
            deadline = time.time() + timeout_sec
            buf = b""
            while time.time() < deadline:
                try:
                    ch = os.read(fd, 1)
                    if ch == b"\n":
                        return buf.decode("utf-8", errors="ignore").strip()
                    if ch != b"\r":
                        buf += ch
                except OSError:
                    time.sleep(0.01)
            return None

        # ── READY 대기 ──────────────────────────────────────
        log_backend_info("ESP32 READY 대기 중...")
        deadline = time.time() + 10
        ready_ok = False
        while time.time() < deadline:
            line = _readline(0.3)
            if line is None:
                continue
            log_backend_info(f"[ESP32] '{line}'")
            if "READY" in line:
                ready_ok = True
                break

        if not ready_ok:
            log_backend_error("ESP32 READY 타임아웃")
            return False, "ESP32 응답 없음", None

        # ── LED ON + GO 전송 ─────────────────────────────────
        GPIO.output(pin, GPIO.HIGH)
        log_backend_info(f"LED ON - GPIO{pin}")
        written = os.write(fd, b"GO\r\n")
        termios.tcdrain(fd)
        log_backend_info(f"GO 전송 완료 ({written} bytes)")

        # ── KEY_HEX 수신 대기 ────────────────────────────────
        deadline = time.time() + 30
        while time.time() < deadline:
            line = _readline(2.0)
            if line is None:
                continue
            log_backend_info(f"[ESP32] '{line}'")
            if "READY" in line:
                # ESP32가 GO를 놓쳤음 (race condition) → GO 재전송
                log_backend_info("GO 재전송 (ESP32가 READY 반복 감지)")
                os.write(fd, b"GO\r\n")
                termios.tcdrain(fd)
                continue
            if line.startswith("KEY_HEX:"):
                hex_key = line[len("KEY_HEX:"):]
                if len(hex_key) != KEY_BYTES * 2:
                    log_backend_error(f"키 길이 오류: {len(hex_key)} chars (expected {KEY_BYTES * 2})")
                    break
                key_bytes = bytes.fromhex(hex_key)
                log_backend_info("키 수신 완료")
                break
            if line.startswith("ERROR"):
                log_backend_error(f"ESP32 오류: {line}")
                break

    except Exception as e:
        log_backend_error(f"ESP32 통신 오류: {e}")
    finally:
        if GPIO is not None:
            GPIO.output(pin, GPIO.LOW)
            log_backend_info(f"LED OFF - GPIO{pin}")
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    if key_bytes is None:
        return False, "키 추출 실패", None
    return True, "OK", key_bytes


# ─── AES-192-CBC 암복호화 ────────────────────────────────────────────────────

def aes_192_encrypt(key: bytes, plaintext: bytes) -> "tuple[bytes, bytes]":
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        raise RuntimeError("cryptography 미설치. 'pip install cryptography' 후 재시도하세요.")
    iv = os.urandom(16)
    padder  = sym_padding.PKCS7(128).padder()
    padded  = padder.update(plaintext) + padder.finalize()
    cipher  = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc     = cipher.encryptor()
    return enc.update(padded) + enc.finalize(), iv


def aes_192_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        raise RuntimeError("cryptography 미설치. 'pip install cryptography' 후 재시도하세요.")
    cipher   = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec      = cipher.decryptor()
    padded   = dec.update(ciphertext) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ─── [변경] 키 명령 핸들러 ───────────────────────────────────────────────────

def handle_key_command(user_id: str, mode: str, key_number: str, data: str) -> str:
    log_backend_info(f"키 명령 수신 - user={user_id}, mode={mode}, key={key_number}")
    normalized_mode = mode.strip().lower()
    normalized_key  = key_number.strip()
    if normalized_mode not in {"encrypt", "decrypt"}:
        return "ERROR: INVALID_MODE"
    if normalized_key not in {"1", "2", "3"}:
        return "ERROR: INVALID_KEY"

    pin_label = {"1": "GPIO17", "2": "GPIO27", "3": "GPIO22"}[normalized_key]
    log_backend_info(f"[STEP 1/2] LED + 캡처 시작 - key={normalized_key}, pin={pin_label}")
    ok, detail, key_bytes = activate_led_and_capture(normalized_key)
    if not ok or key_bytes is None:
        log_backend_error(f"LED/캡처 실패 - detail={detail}")
        return f"ERROR: {detail}"
    log_backend_info(f"[STEP 1/2] LED + 키 추출 완료 - pin={pin_label}")

    log_backend_info(f"[STEP 2/2] AES-192-CBC {normalized_mode} 시작...")
    try:
        if normalized_mode == "encrypt":
            if not data:
                return "ERROR: NO_PLAINTEXT"
            plaintext            = base64.b64decode(data)
            ciphertext, iv       = aes_192_encrypt(key_bytes, plaintext)
            log_backend_info("[STEP 2/2] 암호화 완료")
            log_audit("KEY_ENCRYPT", user_id=user_id, detail=f"key={normalized_key}")
            return f"KEY_ENCRYPT_OK:{ciphertext.hex()}:{iv.hex()}"
        else:
            sep = data.rfind(":")
            if sep < 0:
                return "ERROR: INVALID_DECRYPT_DATA"
            ciphertext = bytes.fromhex(data[:sep])
            iv         = bytes.fromhex(data[sep + 1:])
            plaintext  = aes_192_decrypt(key_bytes, ciphertext, iv)
            log_backend_info("[STEP 2/2] 복호화 완료")
            log_audit("KEY_DECRYPT", user_id=user_id, detail=f"key={normalized_key}")
            return f"KEY_DECRYPT_OK:{base64.b64encode(plaintext).decode('ascii')}"
    except Exception as exc:
        log_backend_error(f"암복호화 실패: {exc}")
        return "ERROR: CRYPTO_FAILED"


# ─── 메인 커맨드 디스패처 ────────────────────────────────────────────────────

def handle_command(command: str) -> str:
    command = command.strip()

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
        parts = command.split(":", 4)
        if len(parts) < 4:
            return "ERROR: INVALID_COMMAND"
        data = parts[4] if len(parts) > 4 else ""
        return handle_key_command(parts[1].strip() or "User", parts[2].strip(), parts[3].strip(), data)

    # ── Bootstrap: DB 비어있을 때만 최초 Root Officer 생성 ──────────────────
    if command.startswith("BOOTSTRAP:"):
        parts = command.split(":", 4)
        if len(parts) != 5:
            return "ERROR: INVALID_COMMAND"
        try:
            password = base64.b64decode(parts[2].strip()).decode("utf-8")
            name     = base64.b64decode(parts[3].strip()).decode("utf-8")
            email    = base64.b64decode(parts[4].strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"BOOTSTRAP 디코딩 실패: {exc}")
            return "ERROR: BOOTSTRAP_FAILED"
        return bootstrap_root_officer(parts[1].strip(), password, name, email)

    # ── 슬롯 생성 (Root Officer 전용) ────────────────────────────────────────
    if command.startswith("CREATE_SLOT:"):
        parts = command.split(":", 2)
        if len(parts) != 3:
            return "ERROR: INVALID_COMMAND"
        try:
            slot_name = base64.b64decode(parts[2].strip()).decode("utf-8")
        except Exception:
            return "ERROR: DECODE_FAILED"
        return create_slot(parts[1].strip(), slot_name)

    # ── 슬롯 내 유저 생성 (Root Officer 전용) ────────────────────────────────
    # CREATE_USER:<root_id>:<slot_id>:<new_id>:<pw_b64>:<name_b64>:<email_b64>:<role_b64>
    if command.startswith("CREATE_USER:"):
        parts = command.split(":", 8)
        if len(parts) != 9:
            return "ERROR: INVALID_COMMAND"
        try:
            password = base64.b64decode(parts[4].strip()).decode("utf-8")
            name     = base64.b64decode(parts[5].strip()).decode("utf-8")
            email    = base64.b64decode(parts[6].strip()).decode("utf-8")
            role     = base64.b64decode(parts[7].strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"CREATE_USER 디코딩 실패: {exc}")
            return "ERROR: DECODE_FAILED"
        return create_user_in_slot(parts[1].strip(), parts[2].strip(),
                                   parts[3].strip(), password, name, email, role)

    # ── 슬롯 목록 조회 ───────────────────────────────────────────────────────
    if command.startswith("LIST_SLOTS:"):
        parts = command.split(":", 1)
        return list_slots_cmd(parts[1].strip() if len(parts) == 2 else "")

    # ── 초대 코드 생성 (Root Officer 전용) ───────────────────────────────────
    # GENERATE_INVITE:<root_id>:<slot_id_b64>:<role_b64>:<expire_days>
    if command.startswith("GENERATE_INVITE:"):
        parts = command.split(":", 4)
        if len(parts) != 5:
            return "ERROR: INVALID_COMMAND"
        try:
            slot_id     = base64.b64decode(parts[2].strip()).decode("utf-8")
            role        = base64.b64decode(parts[3].strip()).decode("utf-8")
            expire_days = int(parts[4].strip())
        except Exception:
            return "ERROR: DECODE_FAILED"
        return generate_invite(parts[1].strip(), slot_id, role, expire_days)

    # ── 초대 코드로 회원가입 ─────────────────────────────────────────────────
    # REGISTER_WITH_INVITE:<code>:<new_id>:<pw_b64>:<name_b64>:<email_b64>
    if command.startswith("REGISTER_WITH_INVITE:"):
        parts = command.split(":", 5)
        if len(parts) != 6:
            return "ERROR: INVALID_COMMAND"
        try:
            password = base64.b64decode(parts[3].strip()).decode("utf-8")
            name     = base64.b64decode(parts[4].strip()).decode("utf-8")
            email    = base64.b64decode(parts[5].strip()).decode("utf-8")
        except Exception:
            return "ERROR: DECODE_FAILED"
        return register_with_invite(parts[1].strip(), parts[2].strip(),
                                    password, name, email)

    if command.startswith("LOGIN:"):
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
        rest = command[len("FIND_ID:"):]
        try:
            name = base64.b64decode(rest.strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"FIND_ID 디코딩 실패: {exc}")
            return "ERROR: NOT_FOUND"
        return find_user_id(name)

    if command.startswith("FIND_PASSWORD:"):
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
        parts = command.split(":", 2)
        if len(parts) != 3:
            return "ERROR: INVALID_COMMAND"
        try:
            new_password = base64.b64decode(parts[2].strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"RESET_PASSWORD 디코딩 실패: {exc}")
            return "ERROR: RESET_FAILED"
        return reset_password(parts[1].strip(), new_password)

    if command.startswith("GET_AUDIT_LOG:"):
        user_id = command.split(":", 1)[1].strip()
        role = get_user_role(user_id)
        if "GET_AUDIT_LOG" not in ROLE_PERMISSIONS.get(role, set()):
            log_audit("AUDIT_LOG_DENIED", user_id=user_id, role=role)
            return "ERROR: PERMISSION_DENIED"
        try:
            if AUDIT_LOG_PATH.exists():
                lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
                recent = lines[-200:]  # 최근 200개
            else:
                recent = []
            payload = base64.b64encode(
                json.dumps(recent, ensure_ascii=False).encode()
            ).decode()
            log_audit("GET_AUDIT_LOG", user_id=user_id, role=role)
            return f"AUDIT_LOG_OK:{payload}"
        except Exception as exc:
            log_backend_error(f"GET_AUDIT_LOG 실패: {exc}")
            return "ERROR: AUDIT_LOG_FAILED"

    if command.startswith("ZEROIZE_PUF:"):
        user_id = command.split(":", 1)[1].strip()
        role = get_user_role(user_id)
        if "ZEROIZE_PUF" not in ROLE_PERMISSIONS.get(role, set()):
            log_audit("ZEROIZE_DENIED", user_id=user_id, role=role)
            return "ERROR: PERMISSION_DENIED"
        # OKM(파생 키) zeroization: 해당 유저의 키 파일 삭제
        safe = sanitize_user_id(user_id)
        user_key_dir = KEY_STORE_DIR / safe
        try:
            if user_key_dir.exists():
                import shutil
                shutil.rmtree(user_key_dir)
            log_backend_info(f"PUF OKM 초기화 완료 - user={user_id}")
            log_audit("ZEROIZE_PUF", user_id=user_id, role=role, detail="OKM zeroized")
            return "ZEROIZE_PUF_OK"
        except Exception as exc:
            log_backend_error(f"ZEROIZE_PUF 실패: {exc}")
            return "ERROR: ZEROIZE_FAILED"

    if command.startswith("ZEROIZE_ALL:"):
        user_id = command.split(":", 1)[1].strip()
        role = get_user_role(user_id)
        if "ZEROIZE_ALL" not in ROLE_PERMISSIONS.get(role, set()):
            log_audit("ZEROIZE_ALL_DENIED", user_id=user_id, role=role)
            return "ERROR: PERMISSION_DENIED"
        try:
            import shutil
            deleted = 0
            if KEY_STORE_DIR.exists():
                for entry in KEY_STORE_DIR.iterdir():
                    if entry.is_dir():
                        shutil.rmtree(entry)
                        deleted += 1
            log_backend_info(f"ZEROIZE_ALL 완료 — {deleted}개 키 디렉터리 삭제 by {user_id}")
            log_audit("ZEROIZE_ALL", user_id=user_id, role=role,
                      detail=f"deleted_dirs={deleted}")
            return "ZEROIZE_ALL_OK"
        except Exception as exc:
            log_backend_error(f"ZEROIZE_ALL 실패: {exc}")
            return "ERROR: ZEROIZE_FAILED"

    # PARTITION_POLICY:<user_id>:<slot_id_b64>:<policy_json_b64>
    if command.startswith("PARTITION_POLICY:"):
        parts = command.split(":", 3)
        if len(parts) != 4:
            return "ERROR: INVALID_COMMAND"
        user_id = parts[1].strip()
        role = get_user_role(user_id)
        if "PARTITION_POLICY" not in ROLE_PERMISSIONS.get(role, set()):
            log_audit("PARTITION_POLICY_DENIED", user_id=user_id, role=role)
            return "ERROR: PERMISSION_DENIED"
        try:
            slot_id    = base64.b64decode(parts[2].strip()).decode("utf-8")
            policy_raw = base64.b64decode(parts[3].strip()).decode("utf-8")
            policy_obj = json.loads(policy_raw)
        except Exception:
            return "ERROR: DECODE_FAILED"
        data = load_users()
        if slot_id not in data["slots"]:
            return "ERROR: SLOT_NOT_FOUND"
        # partition_security_officer는 자신이 속한 슬롯만 수정 가능
        if role == "partition_security_officer":
            safe = sanitize_user_id(user_id)
            if safe not in data["slots"][slot_id].get("users", {}):
                return "ERROR: PERMISSION_DENIED"
        data["slots"][slot_id]["policy"] = policy_obj
        save_users(data)
        log_backend_info(f"파티션 정책 설정 완료 - user={user_id}, slot={slot_id}")
        log_audit("PARTITION_POLICY", user_id=user_id, role=role,
                  detail=f"slot={slot_id}, policy_keys={list(policy_obj.keys())}")
        return "PARTITION_POLICY_OK"

    if command.startswith("SESSION_CLOSE:"):
        return "SESSION_CLOSED"

    log_backend_error(f"알 수 없는 명령: {command[:120]}")
    return "ERROR: UNKNOWN_COMMAND"


# ─── 소켓 수신 ───────────────────────────────────────────────────────────────

def recv_until_newline(conn: "ssl.SSLSocket") -> str:
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
                    data = recv_until_newline(conn)
                    if not data:
                        log_backend_info(f"[TLS 세션 종료] 빈 요청 - client={client_ip}:{client_port}")
                        log_backend_info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                        continue

                    log_backend_info(f"명령 수신 - command={data[:200]}")
                    reply = handle_command(data)
                    log_backend_info(f"응답 전송 - reply={reply[:120]}")
                    conn.sendall((reply + "\n").encode("utf-8"))

                    if data.startswith("START_AUTH:") and reply.startswith("AUTH_OK:"):
                        parts = data.split(":", 2)
                        session_user = parts[1].strip() if len(parts) > 1 else "unknown"
                        log_backend_info(f"[세션 유지] 인증 완료 - user={session_user}, client={client_ip}:{client_port}")

                        while True:
                            cmd = recv_until_newline(conn)

                            if not cmd:
                                log_backend_info(
                                    f"[세션 종료] 클라이언트 연결 끊김 (비정상) "
                                    f"- user={session_user}, client={client_ip}:{client_port}"
                                )
                                break

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
    try:
        main()
    finally:
        if GPIO is not None:
            GPIO.cleanup()