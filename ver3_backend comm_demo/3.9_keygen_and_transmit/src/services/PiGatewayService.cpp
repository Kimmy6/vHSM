#include "PiGatewayService.h"

#include <QByteArray>
#include <QTcpSocket>

namespace {
constexpr quint16 kPiPort = 5000;
constexpr int kConnectTimeoutMs = 3000;
constexpr int kWriteTimeoutMs = 3000;
constexpr int kReadTimeoutMs = 15000;
}

bool PiGatewayService::authenticateUser(const QString &userId,
                                        const QString &piHostOrName,
                                        const QString &publicKeyPem,
                                        QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    if (trimmedUser.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("유저명을 입력해주세요.");
        return false;
    }

    if (publicKeyPem.trimmed().isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("스마트폰에 저장된 공개키 파일을 찾을 수 없습니다. 먼저 공개키를 재발급해주세요.");
        return false;
    }

    const QString publicKeyBase64 = QString::fromLatin1(publicKeyPem.toUtf8().toBase64());
    const QString command = QStringLiteral("AUTH_USER_WITH_PUBKEY:%1:%2")
                                .arg(trimmedUser, publicKeyBase64);

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))
        return false;

    if (reply == QStringLiteral("OK")) {
        if (errorMessage)
            errorMessage->clear();
        return true;
    }

    if (errorMessage)
        *errorMessage = QStringLiteral("ML-DSA 인증에 실패했습니다.\nRaspberry Pi 백엔드 터미널 로그를 확인해주세요.");
    return false;
}

bool PiGatewayService::regeneratePublicKey(const QString &userId,
                                           const QString &piHostOrName,
                                           QString *publicKeyPem,
                                           QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    if (trimmedUser.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("재발급할 유저명을 입력해주세요.");
        return false;
    }

    QString reply;
    if (!sendCommand(piHostOrName,
                     QStringLiteral("REGENERATE_KEY:%1").arg(trimmedUser),
                     &reply,
                     errorMessage)) {
        return false;
    }

    const QString prefix = QStringLiteral("PUBKEY_BASE64:");
    if (!reply.startsWith(prefix)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("공개키 재생성에 실패했습니다.\nRaspberry Pi 백엔드 터미널 로그를 확인해주세요.");
        return false;
    }

    const QByteArray decoded = QByteArray::fromBase64(reply.mid(prefix.size()).toUtf8());
    if (decoded.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("공개키 디코딩에 실패했습니다.");
        return false;
    }

    if (publicKeyPem)
        *publicKeyPem = QString::fromUtf8(decoded);
    if (errorMessage)
        errorMessage->clear();
    return true;
}

bool PiGatewayService::sendCommand(const QString &piHostOrName,
                                   const QString &command,
                                   QString *reply,
                                   QString *errorMessage) const
{
    const QString trimmedHost = piHostOrName.trimmed();
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

    const QByteArray payload = (command + QStringLiteral("\n")).toUtf8();
    if (socket.write(payload) == -1 || !socket.waitForBytesWritten(kWriteTimeoutMs)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Raspberry Pi로 명령을 전송하지 못했습니다.");
        return false;
    }

    if (!socket.waitForReadyRead(kReadTimeoutMs)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Raspberry Pi 서버 응답이 없습니다.");
        return false;
    }

    if (reply)
        *reply = QString::fromUtf8(socket.readAll()).trimmed();
    if (errorMessage)
        errorMessage->clear();
    return true;
}