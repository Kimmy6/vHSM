import RPi.GPIO as GPIO
import time

# 물리적 핀 번호 사용 (BOARD 모드)
PINS = {
    "pin11": 11,
    "pin13": 13,
    "pin15": 15,
}

def setup():
    GPIO.setmode(GPIO.BOARD)  # 물리적 핀 번호 사용
    GPIO.setwarnings(False)
    for pin in PINS.values():
        GPIO.setup(pin, GPIO.OUT)
        GPIO.output(pin, GPIO.LOW)  # 초기값 OFF

def pin_on(pin_number):
    GPIO.output(pin_number, GPIO.HIGH)
    print(f"Pin {pin_number} ON")

def pin_off(pin_number):
    GPIO.output(pin_number, GPIO.LOW)
    print(f"Pin {pin_number} OFF")

def cleanup():
    for pin in PINS.values():
        GPIO.output(pin, GPIO.LOW)
    GPIO.cleanup()
    print("GPIO cleaned up")

if __name__ == "__main__":
    setup()
    try:
        # 예시: 각 핀을 순서대로 1초씩 ON/OFF
        for name, pin in PINS.items():
            print(f"\n--- {name} (Physical Pin {pin}) ---")
            pin_on(pin)
            time.sleep(1)
            pin_off(pin)
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        cleanup()
