#!/usr/bin/env python3
"""
vHSM Officer CLI
----------------
PUF Maintenance Officer / Slot Security Officer 전용 관리 도구.
hsm_cli.py 를 통해 인증 후 호출됩니다.

직접 실행하지 마세요 — python3 hsm_cli.py 로 진입하세요.
"""

import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT   = Path(__file__).resolve().parent
USERS_DB_PATH  = PROJECT_ROOT / "users.json"
KEY_STORE_DIR  = PROJECT_ROOT / "mldsa_crypto" / "generated_keys"
AUDIT_LOG_PATH = PROJECT_ROOT / "audit.log"


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

def log_audit(event: str, user_id: str = "", role: str = "", detail: str = "") -> None:
    entry = json.dumps({
        "timestamp": datetime.utcnow().isoformat(),
        "event":     event,
        "user":      user_id,
        "role":      role,
        "detail":    detail,
    }, ensure_ascii=False)
    try:
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass

def divider(title: str = "") -> None:
    if title:
        print(f"\n{'─' * 20} {title} {'─' * 20}")
    else:
        print("─" * 50)

def _find_slot_for_user(data: dict, user_id: str) -> tuple:
    """user_id 가 속한 (slot_id, slot) 반환. 없으면 (None, None)."""
    for slot_id, slot in data["slots"].items():
        if user_id in slot.get("users", {}):
            return slot_id, slot
    return None, None


# ── PUF Maintenance Officer 메뉴 ─────────────────────────────────────────────

def puf_show_info(user_id: str) -> None:
    divider("PUF 키 파일 현황")
    data = load_db()
    slot_id, slot = _find_slot_for_user(data, user_id)
    print(f"\n  슬롯    : {slot['name'] if slot else '-'} ({slot_id or '-'})")
    print(f"  아이디  : {user_id}")

    key_dir = KEY_STORE_DIR / user_id
    if key_dir.exists():
        files = list(key_dir.iterdir())
        print(f"\n  Pi 측 키 파일 ({len(files)}개):")
        for f in files:
            size = f.stat().st_size
            print(f"    • {f.name}  ({size} bytes)")
    else:
        print("\n  Pi 측 키 파일: 없음 (이미 초기화됨)")


def puf_zeroize(user_id: str) -> None:
    divider("PUF OKM 초기화 (Zeroization)")
    print("\n  ⚠  이 작업은 Pi 측 ML-DSA 키 파일을 영구 삭제합니다.")
    print("     MCU 내 helper data 초기화는 물리적 접근을 통해 별도 수행해야 합니다.")
    print("     삭제 후 해당 계정의 키 재등록이 필요합니다.\n")

    confirm = input("  계속하시겠습니까? (yes 입력): ").strip()
    if confirm.lower() != "yes":
        print("  [취소]")
        return

    key_dir = KEY_STORE_DIR / user_id
    if not key_dir.exists():
        print("  [INFO] 이미 키 파일이 없습니다.")
        return

    try:
        shutil.rmtree(key_dir)
        log_audit("ZEROIZE_PUF", user_id=user_id,
                  role="puf_maintenance_officer",
                  detail=f"Pi-side key files removed: {key_dir}")
        print(f"\n  [완료] Pi 측 키 파일 삭제됨: {key_dir}")
        print("  MCU 측 helper data 초기화는 STM32 직접 접근을 통해 수행하세요.")
    except Exception as e:
        print(f"  [ERROR] 삭제 실패: {e}")


def run_puf_maintenance(user_id: str) -> None:
    print("=" * 50)
    print(f"  vHSM PUF Maintenance CLI  [{user_id}]")
    print("=" * 50)

    while True:
        print("\n┌──────────────────────────────────────┐")
        print("│  [1] Pi 측 PUF 키 파일 현황          │")
        print("│  [2] PUF OKM 초기화 (Zeroization)    │")
        print("│  [0] 종료                             │")
        print("└──────────────────────────────────────┘")

        choice = input("\n선택: ").strip()

        if choice == "1":
            puf_show_info(user_id)
        elif choice == "2":
            puf_zeroize(user_id)
        elif choice == "0":
            print("\n종료합니다.")
            break
        else:
            print("  [ERROR] 올바른 번호를 입력해주세요.")


# ── Slot Security Officer 메뉴 ───────────────────────────────────────────────

def slot_show_partition(user_id: str) -> None:
    divider("내 파티션 현황")
    data   = load_db()
    slot_id, slot = _find_slot_for_user(data, user_id)
    if not slot:
        print("  [ERROR] 소속 슬롯을 찾을 수 없습니다.")
        return

    allowed = slot.get("allowed_roles", [])
    users   = slot.get("users", {})
    print(f"\n  슬롯 ID    : {slot_id}")
    print(f"  슬롯 이름  : {slot['name']}")
    print(f"  생성자     : {slot.get('created_by', '-')}")
    print(f"  허용 역할  : {', '.join(allowed) if allowed else '전체'}")
    print(f"\n  [ 유저 목록 ({len(users)}명) ]")
    for uid, rec in users.items():
        print(f"    • {uid}  ({rec.get('role', '-')})  이름: {rec.get('name', '-')}")


def slot_disable_user(user_id: str) -> None:
    divider("유저 비활성화")
    data    = load_db()
    slot_id, slot = _find_slot_for_user(data, user_id)
    if not slot:
        print("  [ERROR] 소속 슬롯을 찾을 수 없습니다.")
        return

    users = slot.get("users", {})
    if not users:
        print("  슬롯에 유저가 없습니다.")
        return

    print("\n  [ 유저 목록 ]")
    for uid, rec in users.items():
        disabled = " [비활성]" if rec.get("disabled") else ""
        print(f"  • {uid}  ({rec.get('role', '-')}){disabled}")

    target = input("\n  비활성화할 아이디: ").strip()
    if target not in users:
        print("  [ERROR] 해당 유저를 찾을 수 없습니다.")
        return
    if target == user_id:
        print("  [ERROR] 자기 자신은 비활성화할 수 없습니다.")
        return

    confirm = input(f"  '{target}' 을 비활성화합니다. 계속하시겠습니까? (yes): ").strip()
    if confirm.lower() != "yes":
        print("  [취소]")
        return

    users[target]["disabled"] = True
    save_db(data)
    log_audit("USER_DISABLED", user_id=user_id,
              role="partition_security_officer",
              detail=f"target={target}, slot={slot_id}")
    print(f"  [완료] '{target}' 비활성화됨.")


def slot_zeroize_partition(user_id: str) -> None:
    divider("파티션 초기화 (Zeroization)")
    data    = load_db()
    slot_id, slot = _find_slot_for_user(data, user_id)
    if not slot:
        print("  [ERROR] 소속 슬롯을 찾을 수 없습니다.")
        return

    user_count = len(slot.get("users", {}))
    print(f"\n  ⚠  슬롯 '{slot['name']}' 의 유저 {user_count}명 전체를 삭제합니다.")
    print("     이 작업은 되돌릴 수 없습니다.\n")

    confirm = input("  계속하시겠습니까? (yes 입력): ").strip()
    if confirm.lower() != "yes":
        print("  [취소]")
        return

    slot["users"] = {}
    # 해당 슬롯 초대 코드도 무효화
    for inv in data["invite_codes"].values():
        if inv.get("slot_id") == slot_id:
            inv["used"] = True
    save_db(data)
    log_audit("ZEROIZE_PARTITION", user_id=user_id,
              role="partition_security_officer",
              detail=f"slot={slot_id}, users_cleared={user_count}")
    print(f"  [완료] 슬롯 '{slot['name']}' 초기화됨. ({user_count}명 삭제)")


def run_slot_security(user_id: str) -> None:
    print("=" * 50)
    print(f"  vHSM Slot Security CLI  [{user_id}]")
    print("=" * 50)

    while True:
        print("\n┌──────────────────────────────────────┐")
        print("│  [1] 내 파티션 현황                  │")
        print("│  [2] 유저 비활성화                   │")
        print("│  [3] 파티션 초기화 (Zeroization)     │")
        print("│  [0] 종료                             │")
        print("└──────────────────────────────────────┘")

        choice = input("\n선택: ").strip()

        if choice == "1":
            slot_show_partition(user_id)
        elif choice == "2":
            slot_disable_user(user_id)
        elif choice == "3":
            slot_zeroize_partition(user_id)
        elif choice == "0":
            print("\n종료합니다.")
            break
        else:
            print("  [ERROR] 올바른 번호를 입력해주세요.")


# ── 진입점 ───────────────────────────────────────────────────────────────────

def run(user_id: str, role: str) -> None:
    if role == "puf_maintenance_officer":
        run_puf_maintenance(user_id)
    elif role == "partition_security_officer":
        run_slot_security(user_id)
    else:
        print(f"  [ERROR] 지원하지 않는 역할입니다: {role}")
        sys.exit(1)


if __name__ == "__main__":
    print("직접 실행하지 마세요. python3 hsm_cli.py 를 사용하세요.")
    sys.exit(1)
