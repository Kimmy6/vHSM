# Virtual HSM C++/QML Example

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Notes
- This is a minimal C++ + QML scaffold.
- `AuthService` and `CryptoService` currently use mock logic.
- Replace those services with real RSA, file I/O, and key-management logic later.


## Raspberry Pi side example

This project now assumes the Android app only sends a connect-start command to the Pi.
The real progress log should be shown on the Raspberry Pi in LXTerminal.

Example files:
- `pi_backend/pi_gateway.py`: receives `START_USER_CONNECT:<userId>` and launches LXTerminal
- `pi_backend/user_connect_terminal.py`: prints
  - `User 접속 시작`
  - `RSA 인증 중...`
  - `RSA 인증 완료!`
  - `User 접속 중`

The current Qt app still uses a stub transport in `PiGatewayService.cpp`.
Replace that stub with your real Bluetooth or TCP transport later.


## TCP 연결 방법

### 스마트폰 앱(Qt)
- `src/services/PiGatewayService.cpp` 에서 Pi IP와 포트를 사용합니다.
- 기본값:
  - host: `192.168.0.10`
  - port: `5000`
- Raspberry Pi IP에 맞게 `kPiHost` 값을 수정하세요.

### Raspberry Pi 측 준비
1. Raspberry Pi와 스마트폰이 같은 Wi-Fi 네트워크에 연결되어 있어야 합니다.
2. Pi에서 서버 실행:
   ```bash
   cd ~/pi_backend
   python3 tcp_server.py
   ```
3. 스마트폰 앱에서 `가상HSM 접속하기` 버튼 클릭
4. Pi 데스크톱 환경이 켜져 있으면 LXTerminal이 열리고 다음이 출력됩니다:
   - `User 접속 시작`
   - `RSA 인증 중...`
   - `RSA 인증 완료!`
   - `User 접속 중`

### 주의
- `lxterminal` 을 띄우려면 Raspberry Pi Desktop GUI 세션이 실행 중이어야 합니다.
- SSH 헤드리스 상태에서는 창이 뜨지 않습니다.
- 방화벽/네트워크 정책 때문에 포트 5000 접근이 막히면 연결되지 않습니다.
