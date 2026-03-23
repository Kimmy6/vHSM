#include "PiGatewayService.h"

#include <QTcpSocket>

namespace {
constexpr auto kPiHost = "192.168.0.10";   // TODO: change to your Raspberry Pi IP
constexpr quint16 kPiPort = 5000;           // Must match pi_backend/tcp_server.py
constexpr int kConnectTimeoutMs = 3000;
constexpr int kWriteTimeoutMs = 3000;
constexpr int kReadTimeoutMs = 3000;
}

bool PiGatewayService::requestUserConnectStart(const QString &userId, QString *errorMessage) const
{
    const QString trimmed = userId.trimmed();
    if (trimmed.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Please enter a user name.");
        return false;
    }

    QTcpSocket socket;
    socket.connectToHost(QString::fromUtf8(kPiHost), kPiPort);
    if (!socket.waitForConnected(kConnectTimeoutMs)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Could not connect to Raspberry Pi server. Check Pi IP, port, and TCP server status.");
        return false;
    }

    const QByteArray payload = QStringLiteral("START_USER_CONNECT:%1\n").arg(trimmed).toUtf8();
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
