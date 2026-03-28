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

## Tailscale TCP 연결 방법

이 버전은 앱에서 **Pi의 Tailscale IP 또는 MagicDNS 이름을 직접 입력**해서 접속합니다.

### 1. Raspberry Pi 측
Pi와 스마트폰이 **같은 Tailscale 계정**으로 로그인되어 있어야 합니다.

Pi에서 TCP 서버 실행:

```bash
cd /path/to/pi_backend
python3 tcp_server.py
```

서버는 `0.0.0.0:5000` 에서 대기합니다.

Pi의 Tailscale IPv4 확인:

```bash
tailscale ip -4
```

또는 MagicDNS 이름을 사용해도 됩니다.

### 2. 스마트폰 앱 측
Connect 화면에서 아래 두 값을 입력합니다.
- 유저명
- `Pi Tailscale IP 또는 MagicDNS`
  - 예: `100.101.102.103`
  - 예: `raspberrypi.tailnet-name.ts.net`

그 다음 `가상HSM 접속하기` 버튼을 누르면 앱이 Pi의 `tcp_server.py`에

```text
START_USER_CONNECT:<userId>
```

명령을 보냅니다.

### 3. Pi에서 일어나는 일
`tcp_server.py` 는 명령을 받으면 `lxterminal`을 실행하고,
`user_connect_terminal.py` 가 다음 문구를 출력합니다.
- `User 접속 시작`
- `RSA 인증 중...`
- `RSA 인증 완료!`
- `User 접속 중`

## 주의
- `lxterminal` 을 띄우려면 Raspberry Pi Desktop GUI 세션이 실행 중이어야 합니다.
- SSH 헤드리스 상태에서는 창이 뜨지 않습니다.
- 앱에서 Pi로 직접 연결하므로, 스마트폰의 Tailscale이 활성화되어 있어야 합니다.
