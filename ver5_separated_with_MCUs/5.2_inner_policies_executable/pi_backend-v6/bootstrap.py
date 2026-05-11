#!/usr/bin/env python3
"""
vHSM Bootstrap CLI
------------------
Pi에서 직접 실행해서 최초 Root Officer 계정을 생성합니다.
반드시 물리적 접근 환경(로컬 또는 시리얼)에서 실행하세요.

사용법:
    python3 bootstrap.py
"""

import getpass
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

# ── 경로 설정 (tcp_server.py 와 동일한 디렉터리 기준) ────────────────────────
PROJECT_ROOT  = Path(__file__).resolve().parent
USERS_DB_PATH = PROJECT_ROOT / "users.json"

SCRYPT_N        = 2 ** 14
SCRYPT_R        = 8
SCRYPT_P        = 1
SCRYPT_DKLEN    = 32
SCRYPT_SALT_LEN = 16


def load_users() -> dict:
    if not USERS_DB_PATH.exists():
        return {"root_officers": {}, "slots": {}}
    try:
        data = json.loads(USERS_DB_PATH.read_text(encoding="utf-8"))
        if "root_officers" not in data:
            return {"root_officers": {}, "slots": {}}
        if "slots" not in data:
            data["slots"] = {}
        return data
    except Exception:
        return {"root_officers": {}, "slots": {}}


def save_users(data: dict) -> None:
    USERS_DB_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def hash_password(password: str) -> str:
    salt = os.urandom(SCRYPT_SALT_LEN)
    h = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN
    )
    return f"scrypt${salt.hex()}${h.hex()}"


def sanitize_user_id(user_id: str) -> str:
    cleaned = "".join(
        ch if (ch.isalnum() or ch in ("-", "_")) else "_"
        for ch in user_id.strip()
    )
    return cleaned or "User"


def main():
    print("=" * 50)
    print("  vHSM Bootstrap — Root Officer 계정 생성")
    print("=" * 50)
    print()

    # ── DB 비어있는지 확인 ────────────────────────────────────────────────────
    data = load_users()
    if data["root_officers"]:
        print("[ERROR] 이미 Root Officer 계정이 존재합니다.")
        print("        현재 Root Officer 목록:")
        for uid in data["root_officers"]:
            print(f"          - {uid}")
        print()
        print("Bootstrap은 DB가 완전히 비어있을 때만 실행할 수 있습니다.")
        sys.exit(1)

    print("[INFO] DB가 비어있습니다. Root Officer 계정을 생성합니다.")
    print()

    # ── 입력 받기 ─────────────────────────────────────────────────────────────
    user_id = input("아이디: ").strip()
    if not user_id:
        print("[ERROR] 아이디를 입력해주세요.")
        sys.exit(1)
    safe_id = sanitize_user_id(user_id)

    name = input("이름: ").strip()
    if not name:
        print("[ERROR] 이름을 입력해주세요.")
        sys.exit(1)

    email = input("이메일 (선택, 엔터 스킵): ").strip()

    print()
    password = getpass.getpass("비밀번호: ")
    if len(password) < 8:
        print("[ERROR] 비밀번호는 8자 이상이어야 합니다.")
        sys.exit(1)

    password_confirm = getpass.getpass("비밀번호 확인: ")
    if password != password_confirm:
        print("[ERROR] 비밀번호가 일치하지 않습니다.")
        sys.exit(1)

    # ── 계정 생성 ─────────────────────────────────────────────────────────────
    print()
    print(f"[INFO] Root Officer 계정 생성 중... (id={safe_id})")

    data["root_officers"][safe_id] = {
        "password_hash": hash_password(password),
        "name":  name,
        "email": email,
        "role":  "hsm_root_officer",
    }
    save_users(data)

    print()
    print("=" * 50)
    print("  Bootstrap 완료")
    print("=" * 50)
    print(f"  아이디 : {safe_id}")
    print(f"  이름   : {name}")
    print(f"  역할   : HSM Root Officer")
    print()
    print("[INFO] 이제 tcp_server.py 를 실행하고")
    print("       앱에서 위 계정으로 로그인하세요.")
    print()


if __name__ == "__main__":
    main()
