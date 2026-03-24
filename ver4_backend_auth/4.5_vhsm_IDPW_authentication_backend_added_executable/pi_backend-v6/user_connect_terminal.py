from __future__ import annotations

import subprocess
import sys
import time


def log(message: str) -> None:
    print(message, flush=True)


def main() -> None:
    user_id = sys.argv[1] if len(sys.argv) > 1 else "User"

    log(f"{user_id} 접속 시작")
    time.sleep(1)

    log("RSA 인증 중...")
    time.sleep(1.5)

    # Replace this with your real C++ backend call when ready.
    # Example:
    # result = subprocess.run(["/home/pi/vhsm/bin/auth_backend", "rsa_auth", user_id], check=False)
    result = subprocess.run(["python3", "-c", "print('mock auth ok')"], capture_output=True, text=True)

    if result.returncode == 0:
        log("RSA 인증 완료!")
        time.sleep(0.8)
        log(f"{user_id} 접속 중")
    else:
        log("RSA 인증 실패")

    input("\n엔터를 누르면 종료됩니다...")


if __name__ == "__main__":
    main()
