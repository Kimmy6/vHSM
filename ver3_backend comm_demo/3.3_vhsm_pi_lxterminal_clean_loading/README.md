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
