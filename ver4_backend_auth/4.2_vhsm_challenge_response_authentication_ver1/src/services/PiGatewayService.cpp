#include "PiGatewayService.h"

#include <QByteArray>
#include <QStringList>
#include <QTcpSocket>

namespace {
constexpr quint16 kPiPort          = 5000;
constexpr int     kConnectTimeoutMs = 3000;
constexpr int     kWriteTimeoutMs   = 3000;
constexpr int     kReadTimeoutMs    = 15000;
}

bool PiGatewayService::provisionDevice(const QString &userId,
                                       const QString &piHostOrName,
                                       const QString &phonePublicKeyPem,
                                       QString *piPublicKeyPem,
                                       QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    if (trimmedUser.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("유저명을 입력해주세요.");
        return false;
    }

    if (phonePublicKeyPem.trimmed().isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("스마트폰 공개키를 생성하지 못했습니다.");
        return false;
    }

    const QString publicKeyBase64 = QString::fromLatin1(phonePublicKeyPem.toUtf8().toBase64());
    const QString command = QStringLiteral("PROVISION_DEVICE:%1:%2").arg(trimmedUser, publicKeyBase64);

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))
        return false;

    const QString prefix = QStringLiteral("PROVISION_OK:");
    if (!reply.startsWith(prefix)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 공개키 등록에 실패했습니다.\nRaspberry Pi 백엔드 터미널 로그를 확인해주세요.");
        return false;
    }

    const QByteArray decoded = QByteArray::fromBase64(reply.mid(prefix.size()).toUtf8());
    if (decoded.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 공개키 디코딩에 실패했습니다.");
        return false;
    }

    if (piPublicKeyPem)
        *piPublicKeyPem = QString::fromUtf8(decoded);
    if (errorMessage)
        errorMessage->clear();
    return true;
}

bool PiGatewayService::startAuthentication(const QString &userId,
                                           const QString &piHostOrName,
                                           const QByteArray &nonce,
                                           QByteArray *piSignature,
                                           QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    if (trimmedUser.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("유저명을 입력해주세요.");
        return false;
    }

    if (nonce.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Nonce 생성에 실패했습니다.");
        return false;
    }

    // START_AUTH:<userId>:<nonce_b64>
    const QString command = QStringLiteral("START_AUTH:%1:%2")
                                .arg(trimmedUser, QString::fromLatin1(nonce.toBase64()));

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))
        return false;

    const QString prefix = QStringLiteral("AUTH_OK:");
    if (!reply.startsWith(prefix)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 인증에 실패했습니다.\nRaspberry Pi 백엔드 터미널 로그를 확인해주세요.");
        return false;
    }

    const QByteArray sig = QByteArray::fromBase64(reply.mid(prefix.size()).toUtf8());
    if (sig.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 서명 디코딩에 실패했습니다.");
        return false;
    }

    if (piSignature)
        *piSignature = sig;
    if (errorMessage)
        errorMessage->clear();
    return true;
}

bool PiGatewayService::sendKeyCommand(const QString &userId,
                                      const QString &piHostOrName,
                                      const QString &mode,
                                      const QString &keyNumber,
                                      QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    const QString trimmedMode = mode.trimmed().toLower();
    const QString trimmedKey  = keyNumber.trimmed();

    if (trimmedUser.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("유저명이 비어 있습니다. 다시 로그인해주세요.");
        return false;
    }

    if (trimmedMode != QStringLiteral("encrypt") && trimmedMode != QStringLiteral("decrypt")) {
        if (errorMessage)
            *errorMessage = QStringLiteral("알 수 없는 명령입니다.");
        return false;
    }

    if (trimmedKey != QStringLiteral("1") && trimmedKey != QStringLiteral("2") && trimmedKey != QStringLiteral("3")) {
        if (errorMessage)
            *errorMessage = QStringLiteral("키 번호는 1, 2, 3만 사용할 수 있습니다.");
        return false;
    }

    const QString command = QStringLiteral("KEY_COMMAND:%1:%2:%3")
                                .arg(trimmedUser, trimmedMode, trimmedKey);

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))
        return false;

    if (reply == QStringLiteral("OK") || reply == QStringLiteral("KEY_OK")) {
        if (errorMessage)
            errorMessage->clear();
        return true;
    }

    if (errorMessage)
        *errorMessage = reply.isEmpty()
                            ? QStringLiteral("키 명령 처리에 실패했습니다.")
                            : reply;
    return false;
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
        if (errorMessage)
            *errorMessage = QStringLiteral("올바른 User명이나 IP 주소를 입력해주세요.\nTailscale 로그인 상태 및 백엔드 구동 여부를 확인해주세요.");
        return false;
    }

    const QByteArray payload = (command + QStringLiteral("\n")).toUtf8();
    if (socket.write(payload) == -1 || !socket.waitForBytesWritten(kWriteTimeoutMs)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Raspberry Pi로 명령을 전송하지 못했습니다.");
        return false;
    }

    QByteArray responseBuffer;
    while (true) {
        if (!socket.waitForReadyRead(kReadTimeoutMs)) {
            if (responseBuffer.isEmpty()) {
                if (errorMessage)
                    *errorMessage = QStringLiteral("Raspberry Pi 서버 응답이 없습니다.");
                return false;
            }
            break;
        }

        responseBuffer += socket.readAll();
        if (responseBuffer.contains('\n'))
            break;
    }

    const int newlineIndex = responseBuffer.indexOf('\n');
    const QByteArray finalReply = newlineIndex >= 0 ? responseBuffer.left(newlineIndex) : responseBuffer;

    if (reply)
        *reply = QString::fromUtf8(finalReply).trimmed();
    if (errorMessage)
        errorMessage->clear();
    return true;
}
