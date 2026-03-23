#include "PiGatewayService.h"

#include <QByteArray>
#include <QTcpSocket>

namespace {
constexpr quint16 kPiPort = 5000;
constexpr int kConnectTimeoutMs = 3000;
constexpr int kWriteTimeoutMs = 3000;
constexpr int kReadTimeoutMs = 15000;
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

bool PiGatewayService::startMutualAuthentication(const QString &userId,
                                                 const QString &piHostOrName,
                                                 const QByteArray &clientChallenge,
                                                 QString *sessionId,
                                                 QString *piPublicKeyPem,
                                                 QByteArray *serverChallenge,
                                                 QByteArray *piSignature,
                                                 QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    if (trimmedUser.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("유저명을 입력해주세요.");
        return false;
    }

    if (clientChallenge.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("클라이언트 challenge 생성에 실패했습니다.");
        return false;
    }

    const QString command = QStringLiteral("START_MUTUAL_AUTH:%1:%2")
                                .arg(trimmedUser,
                                     QString::fromLatin1(clientChallenge.toBase64()));

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))
        return false;

    const QString prefix = QStringLiteral("AUTH_START_OK:");
    if (!reply.startsWith(prefix)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 상호인증 시작에 실패했습니다.\nRaspberry Pi 백엔드 터미널 로그를 확인해주세요.");
        return false;
    }

    const QStringList parts = reply.split(QLatin1Char(':'));
    if (parts.size() != 5) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 상호인증 응답 형식이 올바르지 않습니다.");
        return false;
    }

    const QByteArray piPub = QByteArray::fromBase64(parts[2].toUtf8());
    const QByteArray serverCh = QByteArray::fromBase64(parts[3].toUtf8());
    const QByteArray piSig = QByteArray::fromBase64(parts[4].toUtf8());
    if (piPub.isEmpty() || serverCh.isEmpty() || piSig.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 상호인증 응답 디코딩에 실패했습니다.");
        return false;
    }

    if (sessionId)
        *sessionId = parts[1];
    if (piPublicKeyPem)
        *piPublicKeyPem = QString::fromUtf8(piPub);
    if (serverChallenge)
        *serverChallenge = serverCh;
    if (piSignature)
        *piSignature = piSig;
    if (errorMessage)
        errorMessage->clear();
    return true;
}

bool PiGatewayService::finishMutualAuthentication(const QString &userId,
                                                  const QString &piHostOrName,
                                                  const QString &sessionId,
                                                  const QByteArray &phoneSignature,
                                                  QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    if (trimmedUser.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("유저명을 입력해주세요.");
        return false;
    }

    if (sessionId.trimmed().isEmpty() || phoneSignature.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("상호인증 완료 데이터가 올바르지 않습니다.");
        return false;
    }

    const QString command = QStringLiteral("FINISH_MUTUAL_AUTH:%1:%2:%3")
                                .arg(trimmedUser,
                                     sessionId.trimmed(),
                                     QString::fromLatin1(phoneSignature.toBase64()));

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))
        return false;

    if (reply == QStringLiteral("OK")) {
        if (errorMessage)
            errorMessage->clear();
        return true;
    }

    if (errorMessage)
        *errorMessage = QStringLiteral("스마트폰 서명 검증에 실패했습니다.\nRaspberry Pi 백엔드 터미널 로그를 확인해주세요.");
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
        if (errorMessage) {
            *errorMessage = QStringLiteral("올바른 User명이나 IP 주소를 입력해주세요.\nTailscale 로그인 상태 및 백엔드 구동 여부를 확인해주세요.")
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
    const QByteArray finalReply = (newlineIndex >= 0)
                                      ? responseBuffer.left(newlineIndex)
                                      : responseBuffer;

    if (reply)
        *reply = QString::fromUtf8(finalReply).trimmed();

    if (errorMessage)
        errorMessage->clear();
    return true;
}
