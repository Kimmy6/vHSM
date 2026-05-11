#!/usr/bin/env python3
"""
vHSM Admin CLI
--------------
Pi에서 직접 실행하는 관리 도구입니다.
users.json 을 직접 읽어 유저/슬롯/초대코드를 조회·관리합니다.

사용법:
    python3 admin_cli.py
"""

import getpass
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT  = Path(__file__).resolve().parent
USERS_DB_PATH = PROJECT_ROOT / "users.json"

# ── DB 헬퍼 ──────────────────────────────────────────────────────────────────

def load_db() -> dict:
    if not USERS_DB_PATH.exists():
        return {"root_officers": {}, "slots": {}, "invite_codes": {}}
    try:
        data = json.loads(USERS_DB_PATH.read_text(encoding="utf-8"))
        data.setdefault("root_officers", {})
        data.setdefault("slots", {})
        data.setdefault("invite_codes", {})
        return data
    except Exception as e:
        print(f"[ERROR] users.json 읽기 실패: {e}")
        sys.exit(1)

def save_db(data: dict) -> None:
    USERS_DB_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
    )

# ── 출력 헬퍼 ─────────────────────────────────────────────────────────────────

def divider(title: str = "") -> None:
    if title:
        print(f"\n{'─' * 20} {title} {'─' * 20}")
    else:
        print("─" * 50)

def role_display(role: str) -> str:
    return {
        "hsm_root_officer":           "HSM Root Officer",
        "puf_maintenance_officer":    "PUF Maintenance Officer",
        "partition_security_officer": "Partition Security Officer",
        "audit_user":                 "Audit User",
        "public_user":                "Public User",
    }.get(role, role)

# ── 메뉴 함수들 ───────────────────────────────────────────────────────────────

def show_users(data: dict) -> None:
    divider("유저 목록")

    print("\n[ Root Officers ]")
    if not data["root_officers"]:
        print("  (없음)")
    for uid, rec in data["root_officers"].items():
        print(f"  • {uid}")
        print(f"      이름  : {rec.get('name', '-')}")
        print(f"      이메일: {rec.get('email', '-') or '-'}")
        print(f"      역할  : {role_display(rec.get('role', 'hsm_root_officer'))}")

    print("\n[ 슬롯 내 유저 ]")
    has_any = False
    for slot_id, slot in data["slots"].items():
        users = slot.get("users", {})
        if not users:
            continue
        has_any = True
        print(f"  슬롯: {slot['name']} ({slot_id})")
        for uid, rec in users.items():
            print(f"    • {uid}")
            print(f"        이름  : {rec.get('name', '-')}")
            print(f"        이메일: {rec.get('email', '-') or '-'}")
            print(f"        역할  : {role_display(rec.get('role', '-'))}")
    if not has_any:
        print("  (없음)")


def show_slots(data: dict) -> None:
    divider("슬롯 목록")
    if not data["slots"]:
        print("\n  (생성된 슬롯 없음)")
        return
    for slot_id, slot in data["slots"].items():
        user_count = len(slot.get("users", {}))
        print(f"\n  • [{slot_id}]  {slot['name']}")
        print(f"      생성자    : {slot.get('created_by', '-')}")
        print(f"      유저 수   : {user_count}명")
        allowed = slot.get("allowed_roles", [])
        print(f"      허용 역할 : {', '.join(allowed) if allowed else '전체'}")


def show_invite_codes(data: dict) -> None:
    divider("초대 코드 목록")
    if not data["invite_codes"]:
        print("\n  (발급된 초대 코드 없음)")
        return
    now = datetime.utcnow()
    for code, inv in data["invite_codes"].items():
        try:
            expires = datetime.fromisoformat(inv["expires_at"])
            expired = now > expires
            expire_str = expires.strftime("%Y-%m-%d %H:%M") + (" [만료]" if expired else "")
        except Exception:
            expire_str = "-"

        status = "사용됨" if inv.get("used") else ("만료" if expired else "유효")
        slot_name = data["slots"].get(inv.get("slot_id", ""), {}).get("name", inv.get("slot_id", "-"))
        print(f"\n  • {code}  [{status}]")
        print(f"      슬롯  : {slot_name}")
        print(f"      역할  : {role_display(inv.get('role', '-'))}")
        print(f"      생성자: {inv.get('created_by', '-')}")
        print(f"      만료  : {expire_str}")


def delete_user(data: dict) -> None:
    divider("유저 삭제")
    uid = input("\n  삭제할 아이디: ").strip()
    if not uid:
        print("  [취소]")
        return

    # root_officers에서 탐색
    if uid in data["root_officers"]:
        confirm = input(f"  Root Officer '{uid}' 을 삭제합니다. 계속하시겠습니까? (yes): ").strip()
        if confirm.lower() != "yes":
            print("  [취소]")
            return
        del data["root_officers"][uid]
        save_db(data)
        print(f"  [완료] '{uid}' 삭제됨.")
        return

    # slots에서 탐색
    for slot_id, slot in data["slots"].items():
        if uid in slot.get("users", {}):
            slot_name = slot["name"]
            confirm = input(f"  슬롯 '{slot_name}' 의 유저 '{uid}' 를 삭제합니다. 계속하시겠습니까? (yes): ").strip()
            if confirm.lower() != "yes":
                print("  [취소]")
                return
            del slot["users"][uid]
            save_db(data)
            print(f"  [완료] '{uid}' 삭제됨.")
            return

    print(f"  [ERROR] '{uid}' 를 찾을 수 없습니다.")


def revoke_invite(data: dict) -> None:
    divider("초대 코드 취소")
    code = input("\n  취소할 초대 코드: ").strip().upper()
    if not code:
        print("  [취소]")
        return
    if code not in data["invite_codes"]:
        print(f"  [ERROR] '{code}' 코드를 찾을 수 없습니다.")
        return
    inv = data["invite_codes"][code]
    if inv.get("used"):
        print("  [INFO] 이미 사용된 코드입니다.")
        return
    inv["used"] = True
    inv["revoked"] = True
    save_db(data)
    print(f"  [완료] 초대 코드 '{code}' 취소됨.")


def delete_slot(data: dict) -> None:
    divider("슬롯 삭제")
    if not data["slots"]:
        print("\n  (슬롯 없음)")
        return
    for slot_id, slot in data["slots"].items():
        print(f"  {slot_id}  →  {slot['name']} (유저 {len(slot.get('users', {}))}명)")
    slot_id = input("\n  삭제할 슬롯 ID: ").strip()
    if not slot_id or slot_id not in data["slots"]:
        print("  [ERROR] 슬롯을 찾을 수 없습니다.")
        return
    slot_name = data["slots"][slot_id]["name"]
    user_count = len(data["slots"][slot_id].get("users", {}))
    confirm = input(f"  슬롯 '{slot_name}' (유저 {user_count}명 포함) 을 삭제합니다. 계속하시겠습니까? (yes): ").strip()
    if confirm.lower() != "yes":
        print("  [취소]")
        return
    del data["slots"][slot_id]
    # 해당 슬롯 초대 코드도 무효화
    for inv in data["invite_codes"].values():
        if inv.get("slot_id") == slot_id:
            inv["used"] = True
    save_db(data)
    print(f"  [완료] 슬롯 '{slot_name}' 삭제됨.")


def _create_user_in_slot(data: dict, slot_id: str, allowed_roles: list, issuer: str) -> bool:
    """슬롯 내 사용자 1명 생성. 성공 시 True 반환."""
    all_roles = [
        ("public_user",                "Public User"),
        ("audit_user",                 "Audit User"),
        ("partition_security_officer", "Partition Security Officer"),
        ("puf_maintenance_officer",    "PUF Maintenance Officer"),
    ]
    selectable = [(r, l) for r, l in all_roles if not allowed_roles or r in allowed_roles]
    if not selectable:
        print("  [ERROR] 허용된 역할이 없습니다.")
        return False

    print("\n  [ 역할 선택 ]")
    for i, (_, label) in enumerate(selectable, 1):
        print(f"  [{i}] {label}")
    role_choice = input("\n  역할 번호: ").strip()
    try:
        role_idx = int(role_choice) - 1
        if not (0 <= role_idx < len(selectable)):
            raise ValueError
    except ValueError:
        print("  [ERROR] 올바른 번호를 입력해주세요.")
        return False
    role, role_label = selectable[role_idx]

    new_id = input("  아이디: ").strip()
    if not new_id:
        print("  [취소]")
        return False

    # 전체 DB 중복 검사
    if new_id in data["root_officers"]:
        print("  [ERROR] 이미 존재하는 아이디입니다.")
        return False
    for slot in data["slots"].values():
        if new_id in slot.get("users", {}):
            print("  [ERROR] 이미 존재하는 아이디입니다.")
            return False

    name = input("  이름: ").strip()
    if not name:
        print("  [취소]")
        return False

    import getpass as gp
    password = gp.getpass("  비밀번호: ")
    password_confirm = gp.getpass("  비밀번호 확인: ")
    if password != password_confirm:
        print("  [ERROR] 비밀번호가 일치하지 않습니다.")
        return False
    if len(password) < 8:
        print("  [ERROR] 비밀번호는 8자 이상이어야 합니다.")
        return False

    import hashlib, os as _os
    salt = _os.urandom(16)
    h = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    pw_hash = f"scrypt${salt.hex()}${h.hex()}"

    data["slots"][slot_id]["users"][new_id] = {
        "password_hash": pw_hash,
        "name":          name,
        "email":         "",
        "role":          role,
    }
    save_db(data)
    print(f"  [완료] {role_label} 계정 '{new_id}' 생성됨.")
    return True


def create_slot(data: dict) -> None:
    divider("슬롯 생성")

    issuer = input("\n  생성자 Root Officer ID: ").strip()
    if not issuer or issuer not in data["root_officers"]:
        print("  [ERROR] 존재하지 않는 Root Officer ID 입니다.")
        return

    slot_name = input("  슬롯 이름: ").strip()
    if not slot_name:
        print("  [취소]")
        return

    assignable_roles = [
        ("public_user",                "Public User"),
        ("audit_user",                 "Audit User"),
        ("partition_security_officer", "Partition Security Officer"),
        ("puf_maintenance_officer",    "PUF Maintenance Officer"),
    ]
    print("\n  [ 이 슬롯에서 허용할 역할 선택 (복수 선택, 쉼표 구분) ]")
    for i, (_, label) in enumerate(assignable_roles, 1):
        print(f"  [{i}] {label}")
    print("  [Enter] 전체 허용")
    role_input = input("\n  번호 입력 (예: 1,2): ").strip()

    if not role_input:
        allowed_roles = [r for r, _ in assignable_roles]
    else:
        allowed_roles = []
        for token in role_input.split(","):
            token = token.strip()
            try:
                idx = int(token) - 1
                if 0 <= idx < len(assignable_roles):
                    allowed_roles.append(assignable_roles[idx][0])
            except ValueError:
                pass
        if not allowed_roles:
            print("  [ERROR] 올바른 번호를 입력해주세요.")
            return

    import uuid
    slot_id = "slot_" + uuid.uuid4().hex[:8]
    data["slots"][slot_id] = {
        "name":          slot_name,
        "created_by":    issuer,
        "allowed_roles": allowed_roles,
        "users":         {},
    }
    save_db(data)
    role_labels = [label for r, label in assignable_roles if r in allowed_roles]
    print(f"\n  [완료] 슬롯 생성됨")
    print(f"      ID      : {slot_id}")
    print(f"      이름    : {slot_name}")
    print(f"      허용역할: {', '.join(role_labels)}")

    # ── 슬롯 생성 직후 사용자 추가 서브 플로우 ────────────────────────────────
    while True:
        add_user = input("\n  이 슬롯에 사용자를 바로 추가하시겠습니까? (y/n): ").strip().lower()
        if add_user != "y":
            break
        divider("사용자 추가")
        _create_user_in_slot(data, slot_id, allowed_roles, issuer)
        # save_db는 _create_user_in_slot 내부에서 호출됨
        # data를 최신으로 다시 로드
        data = load_db()


def generate_invite_code(data: dict) -> None:
    divider("초대 코드 발급")

    if not data["slots"]:
        print("\n  [ERROR] 슬롯이 없습니다. 먼저 [6] 슬롯 생성을 실행해주세요.")
        return

    print("\n  [ 슬롯 목록 ]")
    slot_ids = list(data["slots"].keys())
    for i, sid in enumerate(slot_ids, 1):
        slot = data["slots"][sid]
        allowed = slot.get("allowed_roles", [])
        allowed_str = ", ".join(allowed) if allowed else "전체"
        print(f"  [{i}] {slot['name']}  ({sid})  허용역할: {allowed_str}")
    slot_choice = input("\n  슬롯 번호 선택: ").strip()
    try:
        slot_idx = int(slot_choice) - 1
        if not (0 <= slot_idx < len(slot_ids)):
            raise ValueError
    except ValueError:
        print("  [ERROR] 올바른 번호를 입력해주세요.")
        return
    slot_id   = slot_ids[slot_idx]
    slot_name = data["slots"][slot_id]["name"]

    # 슬롯의 allowed_roles 기준으로 선택 가능 역할 필터링
    all_roles = [
        ("public_user",                "Public User"),
        ("audit_user",                 "Audit User"),
        ("partition_security_officer", "Partition Security Officer"),
        ("puf_maintenance_officer",    "PUF Maintenance Officer"),
    ]
    slot_allowed = data["slots"][slot_id].get("allowed_roles", [])
    assignable_roles = [(r, l) for r, l in all_roles if not slot_allowed or r in slot_allowed]
    if not assignable_roles:
        print("  [ERROR] 이 슬롯에 허용된 역할이 없습니다.")
        return
    print("\n  [ 역할 선택 ]")
    for i, (_, label) in enumerate(assignable_roles, 1):
        print(f"  [{i}] {label}")
    role_choice = input("\n  역할 번호 선택: ").strip()
    try:
        role_idx = int(role_choice) - 1
        if not (0 <= role_idx < len(assignable_roles)):
            raise ValueError
    except ValueError:
        print("  [ERROR] 올바른 번호를 입력해주세요.")
        return
    role, role_label = assignable_roles[role_idx]

    expire_input = input("\n  유효기간 (일, 기본 7): ").strip()
    try:
        expire_days = max(1, int(expire_input)) if expire_input else 7
    except ValueError:
        print("  [ERROR] 숫자를 입력해주세요.")
        return

    issuer = input("\n  발급자 Root Officer ID: ").strip()
    if not issuer or issuer not in data["root_officers"]:
        print("  [ERROR] 존재하지 않는 Root Officer ID 입니다.")
        return

    import random
    import string
    from datetime import timedelta

    while True:
        code = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
        if code not in data["invite_codes"]:
            break

    expires_at = (datetime.utcnow() + timedelta(days=expire_days)).isoformat()
    data["invite_codes"][code] = {
        "slot_id":    slot_id,
        "role":       role,
        "created_by": issuer,
        "expires_at": expires_at,
        "used":       False,
    }
    save_db(data)

    print(f"\n  ┌─────────────────────────────────────┐")
    print(f"  │  초대 코드 발급 완료                 │")
    print(f"  │                                     │")
    print(f"  │    코드  :  {code:<25s}│")
    print(f"  │    슬롯  :  {slot_name:<25s}│")
    print(f"  │    역할  :  {role_label:<25s}│")
    print(f"  │    만료  :  {expires_at[:10]:<25s}│")
    print(f"  └─────────────────────────────────────┘")
    print(f"\n  이 코드를 대상 유저에게 전달하세요.")


# ── 메인 ─────────────────────────────────────────────────────────────────────

def run(user_id: str) -> None:
    """hsm_cli.py 에서 인증 후 호출되는 진입점."""
    print("=" * 50)
    print(f"  vHSM Admin CLI  [{user_id}]")
    print("=" * 50)

    while True:
        print("\n┌─────────────────────────────┐")
        print("│  [1] 유저 목록 보기          │")
        print("│  [2] 슬롯 목록 보기          │")
        print("│  [3] 초대 코드 목록 보기     │")
        print("│  [4] 유저 삭제               │")
        print("│  [5] 초대 코드 취소          │")
        print("│  [6] 슬롯 생성               │")
        print("│  [7] 슬롯 삭제               │")
        print("│  [8] 초대 코드 발급          │")
        print("│  [0] 종료                    │")
        print("└─────────────────────────────┘")

        choice = input("\n선택: ").strip()
        data = load_db()

        if choice == "1":
            show_users(data)
        elif choice == "2":
            show_slots(data)
        elif choice == "3":
            show_invite_codes(data)
        elif choice == "4":
            delete_user(data)
        elif choice == "5":
            revoke_invite(data)
        elif choice == "6":
            create_slot(data)
        elif choice == "7":
            delete_slot(data)
        elif choice == "8":
            generate_invite_code(data)
        elif choice == "0":
            print("\n종료합니다.")
            break
        else:
            print("  [ERROR] 올바른 번호를 입력해주세요.")


def main() -> None:
    print("=" * 50)
    print("  vHSM Admin CLI")
    print("=" * 50)

    if not USERS_DB_PATH.exists():
        print("\n[ERROR] users.json 이 없습니다. bootstrap.py 를 먼저 실행해주세요.")
        sys.exit(1)

    run("root")


if __name__ == "__main__":
    main()