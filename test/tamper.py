from gpiozero import Button
import time

tamper = Button(21, pull_up=False)

# 이벤트 말고 일단 상태만 계속 출력
while True:
    print(f"핀 상태: {'HIGH' if tamper.is_pressed else 'LOW'}")
    time.sleep(0.5)