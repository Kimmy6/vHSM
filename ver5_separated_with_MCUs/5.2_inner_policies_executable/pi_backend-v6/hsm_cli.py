#!/usr/bin/env python3
"""
vHSM CLI 진입점
---------------
모든 백엔드 관리자가 이 스크립트로 로그인합니다.
ID/PW 검증 후 역할에 따라 적절한 CLI로 라우팅됩니다.

사용법:
    python3 hsm_cli.py
"""

import getpass
import hashlib
import hmac
import json
import sys
from pathlib import Path

PROJECT_ROOT  = Path(__file__).resolve().parent
USERS_DB_PATH = PROJECT_ROOT / "users.json"

SCRYPT_N      = 2 ** 14
SCRYPT_R      = 8
SCRYPT_P      = 1
SCRYPT_DKLEN  = 32

# 백엔드 CLI 접근 가능 역할
ALLOWED_ROLES = {
    "hsm_root_officer",
    "puf_maintenance_officer",
    "partition_security_officer",
}

ROLE_LABELS = {
    "hsm_root_officer":           "HSM Root Officer",
    "puf_maintenance_officer":    "PUF Maintenance Officer",
    "partition_security_officer": "Slot Security Officer",
}


def load_db() -> dict:
    if not USERS_DB_PATH.exists():
        print("[ERROR] users.json 이 없습니다. bootstrap.py 를 먼저 실행해주세요.")
        sys.exit(1)
    try:
        data = json.loads(USERS_DB_PATH.read_text(encoding="utf-8"))
        data.setdefault("root_officers", {})
        data.setdefault("slots", {})
        return data
    except Exception as e:
        print(f"[ERROR] users.json 읽기 실패: {e}")
        sys.exit(1)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        parts = stored_hash.split("$")
        if len(parts) != 3 or parts[0] != "scrypt":
            return False
        salt     = bytes.fromhex(parts[1])
        expected = bytes.fromhex(parts[2])
        computed = hashlib.scrypt(
            password.encode("utf-8"), salt=salt,
            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN
        )
        return hmac.compare_digest(computed, expected)
    except Exception:
        return False


def find_record(user_id: str, data: dict) -> tuple:
    """(record, role) 반환. 없으면 (None, '')."""
    if user_id in data["root_officers"]:
        rec = data["root_officers"][user_id]
        return rec, rec.get("role", "hsm_root_officer")
    for slot in data["slots"].values():
        if user_id in slot.get("users", {}):
            rec = slot["users"][user_id]
            return rec, rec.get("role", "")
    return None, ""


def login() -> tuple:
    """로그인 시도. (user_id, role) 반환. 실패 시 sys.exit."""
    MAX_ATTEMPTS = 3
    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"\n  로그인 ({attempt}/{MAX_ATTEMPTS})")
        user_id  = input("  아이디  : ").strip()
        password = getpass.getpass("  비밀번호: ")

        if not user_id or not password:
            print("  [ERROR] 아이디와 비밀번호를 입력해주세요.")
            continue

        data   = load_db()
        record, role = find_record(user_id, data)

        # 타이밍 공격 방지: 레코드 없어도 검증 수행
        dummy  = "scrypt$" + "00" * 16 + "$" + "00" * 32
        stored = record["password_hash"] if record else dummy
        valid  = verify_password(password, stored)

        if not record or not valid:
            print("  [ERROR] 아이디 또는 비밀번호가 잘못되었습니다.")
            continue

        if role not in ALLOWED_ROLES:
            print(f"  [ERROR] 이 계정은 CLI 접근 권한이 없습니다. (role: {role})")
            sys.exit(1)

        # 비활성화 계정 체크
        if record.get("disabled"):
            print("  [ERROR] 비활성화된 계정입니다. Slot Security Officer에게 문의하세요.")
            sys.exit(1)

        return user_id, role

    print("\n  [ERROR] 로그인 실패 횟수 초과. 종료합니다.")
    sys.exit(1)


def main() -> None:
    print("=" * 50)
    print("  vHSM Backend CLI")
    print("=" * 50)

    user_id, role = login()
    label = ROLE_LABELS.get(role, role)
    print(f"\n  ✓ 로그인 성공 — {label} ({user_id})")

    if role == "hsm_root_officer":
        import admin_cli
        admin_cli.run(user_id)

    elif role in ("puf_maintenance_officer", "partition_security_officer"):
        import officer_cli
        officer_cli.run(user_id, role)


if __name__ == "__main__":
    main()
