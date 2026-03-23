#include "PiGatewayService.h"

#include <QTcpSocket>

namespace {
constexpr quint16 kPiPort = 5000;           // Must match pi_backend/tcp_server.py
constexpr int kConnectTimeoutMs = 3000;
constexpr int kWriteTimeoutMs = 3000;
constexpr int kReadTimeoutMs = 3000;
}

bool PiGatewayService::requestUserConnectStart(const QString &userId,
                                               const QString &piHostOrName,
                                               QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    const QString trimmedHost = piHostOrName.trimmed();

    if (trimmedUser.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("유저명을 입력해주세요.");
        return false;
    }

    if (trimmedHost.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Tailscale IP 주소를 입력해주세요.");
        return false;
    }

    QTcpSocket socket;
    socket.connectToHost(trimmedHost, kPiPort);
    if (!socket.waitForConnected(kConnectTimeoutMs)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("IP 주소 %1:%2 를 찾을 수 없습니다.\nTailscale 로그인 상태 및 백엔드 구동 여부를 확인해주세요.")
                                .arg(trimmedHost)
                                .arg(kPiPort);
        }
        return false;
    }

    const QByteArray payload =
        QStringLiteral("START_USER_CONNECT:%1\n").arg(trimmedUser).toUtf8();
    if (socket.write(payload) == -1 || !socket.waitForBytesWritten(kWriteTimeoutMs)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Failed to send command to Raspberry Pi.");
        return false;
    }

    if (!socket.waitForReadyRead(kReadTimeoutMs)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("No response from Raspberry Pi server.");
        return false;
    }

    const QString reply = QString::fromUtf8(socket.readAll()).trimmed();
    if (reply != QStringLiteral("OK")) {
        if (errorMessage)
            *errorMessage = reply.isEmpty()
                ? QStringLiteral("Unexpected response from Raspberry Pi.")
                : QStringLiteral("Raspberry Pi error: %1").arg(reply);
        return false;
    }

    if (errorMessage)
        errorMessage->clear();
    return true;
}
