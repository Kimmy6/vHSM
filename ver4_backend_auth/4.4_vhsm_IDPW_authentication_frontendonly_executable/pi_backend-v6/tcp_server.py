from __future__ import annotations

import base64
import secrets
import socket
import ssl
import subprocess
import time
import os
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

PROJECT_ROOT = Path(__file__).resolve().parent
MLDSA_DIR    = PROJECT_ROOT / "mldsa_crypto"
KEY_STORE_DIR = MLDSA_DIR / "generated_keys"

AUTH_BINARY   = MLDSA_DIR / "mldsa_auth"
KEYGEN_BINARY = MLDSA_DIR / "mldsa_keygen"

# TLS 인증서/키 경로 (ECDSA P-256, self-signed)
TLS_CERT_PATH = PROJECT_ROOT / "tls_cert.pem"
TLS_KEY_PATH  = PROJECT_ROOT / "tls_key.pem"


# ─────────────────────────────────────────────
# 로깅
# ─────────────────────────────────────────────

def log_backend_info(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [BACKEND INFO] {message}", flush=True)


def log_backend_error(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [BACKEND ERROR] {message}", flush=True)


# ─────────────────────────────────────────────
# TLS 인증서 생성 (최초 1회)
# openssl로 ECDSA P-256 self-signed 인증서 생성
# ─────────────────────────────────────────────

def ensure_tls_cert() -> tuple[Path, Path]:
    if TLS_CERT_PATH.exists() and TLS_KEY_PATH.exists():
        return TLS_CERT_PATH, TLS_KEY_PATH

    log_backend_info("TLS 인증서가 없습니다. 새로 생성합니다.")
    result = subprocess.run(
        [
            "openssl", "req", "-x509",
            "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:P-256",
            "-keyout", str(TLS_KEY_PATH),
            "-out",    str(TLS_CERT_PATH),
            "-days",   "3650",
            "-nodes",
            "-subj",   "/CN=vHSM-Pi",
        ],
        capture_output=True,
        text=True,
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
    ctx.verify_mode = ssl.CERT_NONE  # 클라이언트 인증서는 요구하지 않음
    return ctx


# ─────────────────────────────────────────────
# 유틸
# ─────────────────────────────────────────────

def sanitize_user_id(user_id: str) -> str:
    cleaned = "".join(ch if (ch.isalnum() or ch in ("-", "_")) else "_" for ch in user_id.strip())
    return cleaned or "User"


def run_checked(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=str(cwd), capture_output=True, text=True, check=False)


def ensure_pi_keypair(user_id: str) -> tuple[Path, Path]:
    safe_user = sanitize_user_id(user_id)
    user_dir  = KEY_STORE_DIR / safe_user
    user_dir.mkdir(parents=True, exist_ok=True)

    seed_file         = user_dir / "pi_seed.hex"
    private_key_path  = user_dir / "pi_mldsa_private.pem"
    public_key_path   = user_dir / "pi_mldsa_public.pem"
    cert_key_path     = user_dir / "pi_mldsa_cert.pem"

    if private_key_path.exists() and public_key_path.exists():
        return private_key_path, public_key_path

    seed_hex = secrets.token_hex(32)
    seed_file.write_text(seed_hex + "\n", encoding="utf-8")

    result = run_checked(
        [str(KEYGEN_BINARY), str(seed_file), str(private_key_path),
         str(public_key_path), str(cert_key_path), safe_user],
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
        [str(AUTH_BINARY), "sign", str(private_key_path),
         base64.b64encode(message_bytes).decode("ascii")],
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


# ─────────────────────────────────────────────
# 단방향 인증 페이로드: PI_AUTH|<userId>|<nonce_b64>
# AppController.cpp buildPiAuthPayload() 와 반드시 일치
# ─────────────────────────────────────────────

def build_pi_auth_payload(user_id: str, nonce_b64: str) -> bytes:
    return f"PI_AUTH|{user_id}|{nonce_b64}".encode("utf-8")


# ─────────────────────────────────────────────
# 커맨드 핸들러
# ─────────────────────────────────────────────

def provision_device(user_id: str, phone_public_key_pem: str) -> str:
    """
    초기 1회 공개키 교환 (TOFU).
    Pi 공개키(ML-DSA) + TLS 인증서를 함께 반환.
    응답: PROVISION_OK:<pi_pub_b64>:<tls_cert_b64>
    """
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
    """
    단방향 인증: 앱이 보낸 nonce를 Pi 개인키로 서명해서 반환.
    앱은 PROVISION 시 저장한 Pi ML-DSA 공개키로 서명을 검증.
    응답: AUTH_OK:<pi_sig_b64>
    """
    log_backend_info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log_backend_info(f"[STEP 1/5] Challenge-Response 인증 시작 - user={user_id}")

    if not AUTH_BINARY.exists():
        log_backend_error(f"ML-DSA 인증 바이너리를 찾을 수 없습니다. ({AUTH_BINARY})")
        return "ERROR: AUTH_FAILED"

    # ── STEP 2: nonce(challenge) 수신 및 검증 ──────────────────────
    try:
        nonce_bytes = base64.b64decode(nonce_b64, validate=True)
    except Exception as exc:
        log_backend_error(f"nonce Base64 디코딩 실패 - user={user_id}, detail={exc}")
        return "ERROR: AUTH_FAILED"

    nonce_preview = nonce_bytes.hex()[:16] + "..."  # 앞 8바이트(16 hex chars)만 표시
    log_backend_info(
        f"[STEP 2/5] 앱으로부터 Challenge(nonce) 수신 완료 - "
        f"user={user_id}, nonce_len={len(nonce_bytes)}bytes, nonce_preview=0x{nonce_preview}"
    )

    # ── STEP 3: Pi 개인키로 페이로드 서명 ─────────────────────────
    try:
        pi_private_key_path, pi_public_key_path = ensure_pi_keypair(user_id)
    except Exception as exc:
        log_backend_error(f"Pi 키쌍 로드 실패 - user={user_id}, detail={exc}")
        return "ERROR: AUTH_FAILED"

    pi_payload = build_pi_auth_payload(user_id, nonce_b64)
    log_backend_info(
        f"[STEP 3/5] 서명 페이로드 구성 완료 - "
        f"payload=PI_AUTH|{user_id}|<nonce_b64>, payload_len={len(pi_payload)}bytes"
    )

    log_backend_info(f"[STEP 3/5] Pi ML-DSA 개인키로 서명 중... (key={pi_private_key_path.name})")
    try:
        pi_signature_b64 = sign_with_private_key(pi_private_key_path, pi_payload)
    except Exception as exc:
        log_backend_error(f"Pi 서명 실패 - user={user_id}, detail={exc}")
        return "ERROR: AUTH_FAILED"

    sig_bytes = base64.b64decode(pi_signature_b64)
    sig_preview = sig_bytes.hex()[:16] + "..."
    log_backend_info(
        f"[STEP 4/5] ML-DSA 서명 생성 완료 - "
        f"sig_len={len(sig_bytes)}bytes, sig_preview=0x{sig_preview}"
    )

    # ── STEP 5: 서명값 전송 ────────────────────────────────────────
    log_backend_info(
        f"[STEP 5/5] 서명값 앱으로 전송 - "
        f"user={user_id} → 앱이 저장된 Pi 공개키({pi_public_key_path.name})로 검증"
    )
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
        log_backend_error(f"지원하지 않는 키 명령 mode={mode}")
        return "ERROR: INVALID_MODE"

    if normalized_key not in {"1", "2", "3"}:
        log_backend_error(f"지원하지 않는 키 번호 key={key_number}")
        return "ERROR: INVALID_KEY"

    ok, detail = send_key_command_to_arduino(normalized_mode, normalized_key)
    if not ok:
        log_backend_error(f"Arduino 키 명령 실패 - user={user_id}, detail={detail}")
        return f"ERROR: {detail}"

    pin_label = {"1": "D3", "2": "D4", "3": "D5"}[normalized_key]
    log_backend_info(f"Arduino 키 명령 완료 - user={user_id}, key={normalized_key}, pin={pin_label}")
    return "KEY_OK"


def handle_command(command: str) -> str:
    command = command.strip()

    if command.startswith("PROVISION_DEVICE:"):
        parts = command.split(":", 2)
        if len(parts) != 3:
            log_backend_error(f"PROVISION_DEVICE 명령 형식 오류: {command[:200]}")
            return "ERROR: INVALID_COMMAND"
        user_id = parts[1].strip() or "User"
        try:
            phone_public_key_pem = base64.b64decode(parts[2].strip()).decode("utf-8")
        except Exception as exc:
            log_backend_error(f"스마트폰 공개키 Base64 디코딩 실패 - user={user_id}, detail={exc}")
            return "ERROR: PROVISION_FAILED"
        return provision_device(user_id, phone_public_key_pem)

    if command.startswith("START_AUTH:"):
        parts = command.split(":", 2)
        if len(parts) != 3:
            log_backend_error(f"START_AUTH 명령 형식 오류: {command[:200]}")
            return "ERROR: INVALID_COMMAND"
        return start_auth(parts[1].strip() or "User", parts[2].strip())

    if command.startswith("KEY_COMMAND:"):
        parts = command.split(":", 3)
        if len(parts) != 4:
            log_backend_error(f"KEY_COMMAND 명령 형식 오류: {command[:200]}")
            return "ERROR: INVALID_COMMAND"
        return handle_key_command(parts[1].strip() or "User", parts[2].strip(), parts[3].strip())

    log_backend_error(f"알 수 없는 명령을 수신했습니다: {command[:120]}")
    return "ERROR: UNKNOWN_COMMAND"


# ─────────────────────────────────────────────
# 소켓 수신
# ─────────────────────────────────────────────

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


# ─────────────────────────────────────────────
# 메인 루프
# ─────────────────────────────────────────────

def main() -> None:
    KEY_STORE_DIR.mkdir(parents=True, exist_ok=True)

    # TLS 인증서 준비
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

            # TLS 핸드셰이크
            try:
                conn = ssl_ctx.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as exc:
                log_backend_error(f"TLS 핸드셰이크 실패 - client={client_ip}:{client_port}, detail={exc}")
                raw_conn.close()
                continue

            with conn:
                try:
                    data = recv_until_newline(conn)

                    if not data:
                        log_backend_error(f"빈 요청 - client={client_ip}:{client_port}")
                        continue

                    log_backend_info(f"명령 수신 - client={client_ip}:{client_port}, command={data[:200]}")
                    reply = handle_command(data)
                    log_backend_info(f"응답 전송 - client={client_ip}:{client_port}, reply={reply[:120]}")
                    conn.sendall((reply + "\n").encode("utf-8"))

                except Exception as exc:
                    log_backend_error(f"클라이언트 처리 중 예외 - client={client_ip}:{client_port}, detail={exc}")
                    try:
                        conn.sendall(b"ERROR: INTERNAL_SERVER_ERROR\n")
                    except Exception:
                        pass


if __name__ == "__main__":
    main()
