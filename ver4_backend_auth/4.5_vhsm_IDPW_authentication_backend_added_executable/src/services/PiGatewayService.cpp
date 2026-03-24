#include "PiGatewayService.h"
#include "FileUtils.h"

#include <QDebug>
#include <QByteArray>
#include <QFile>
#include <QStringList>
#include <QSslSocket>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>

namespace {
constexpr quint16 kPiPort           = 5000;
constexpr int     kConnectTimeoutMs = 5000;
constexpr int     kWriteTimeoutMs   = 3000;
constexpr int     kReadTimeoutMs    = 15000;
}

// ─────────────────────────────────────────────
// TLS 1.3 연결 헬퍼
//
// pinnedCertPath 비어 있음 → VerifyNone (PROVISION 최초 1회, TOFU)
// pinnedCertPath 있음      → 저장된 인증서와 핑거프린트 비교 (핀닝)
// ─────────────────────────────────────────────
bool PiGatewayService::sendCommand(const QString &piHostOrName,
                                   const QString &command,
                                   QString *reply,
                                   QString *errorMessage,
                                   const QString &pinnedCertPath) const
{
    const QString trimmedHost = piHostOrName.trimmed();
    if (trimmedHost.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Tailscale IP 주소를 입력해주세요.");
        return false;
    }

    QSslSocket socket;

    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setProtocol(QSsl::TlsV1_3OrLater);

    QSslCertificate pinnedCert;

    if (pinnedCertPath.isEmpty()) {
        // PROVISION: VerifyNone
        sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);  // [FIX] sslConfig에 직접 설정
        socket.setSslConfiguration(sslConfig);                // [FIX] 이 다음에 적용
    } else {
        QFile certFile(pinnedCertPath);
        if (!certFile.open(QIODevice::ReadOnly)) {
            if (errorMessage)
                *errorMessage = QStringLiteral("저장된 Pi TLS 인증서를 불러오지 못했습니다.\n먼저 '공개키 등록'을 진행해주세요.");
            return false;
        }
        pinnedCert = QSslCertificate(&certFile, QSsl::Pem);
        certFile.close();

        if (pinnedCert.isNull()) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Pi TLS 인증서가 유효하지 않습니다.");
            return false;
        }

        sslConfig.setCaCertificates({pinnedCert});
        socket.setSslConfiguration(sslConfig);
        socket.setPeerVerifyMode(QSslSocket::VerifyPeer);

        // [FIX] IP 접속 시 호스트명 불일치 에러 추가 허용 (핀닝으로 직접 검증하므로 안전)
        socket.ignoreSslErrors({
            QSslError(QSslError::SelfSignedCertificate, pinnedCert),
            QSslError(QSslError::CertificateUntrusted,  pinnedCert),
            QSslError(QSslError::HostNameMismatch,       pinnedCert),
        });
    }

    socket.setSslConfiguration(sslConfig);

    socket.connectToHostEncrypted(trimmedHost, kPiPort);
    if (!socket.waitForEncrypted(kConnectTimeoutMs)) {
        const auto sslErrs = socket.sslHandshakeErrors();
        const QString sslErr = sslErrs.isEmpty()
                                   ? QStringLiteral("(no ssl errors)")
                                   : sslErrs.first().errorString();
        qDebug() << "TLS fail:" << socket.errorString() << "| SSL:" << sslErr;

        if (errorMessage)
            *errorMessage = QStringLiteral("TLS 연결에 실패했습니다.\n백엔드 서버 상태를 확인해주세요.\n") + socket.errorString();
        return false;
    }

    // 핀닝 검증: 서버 인증서 핑거프린트가 저장된 것과 일치하는지 확인
    if (!pinnedCert.isNull()) {
        const QSslCertificate serverCert = socket.peerCertificate();
        if (serverCert.digest(QCryptographicHash::Sha256)
                != pinnedCert.digest(QCryptographicHash::Sha256)) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Pi TLS 인증서가 저장된 것과 다릅니다. 접속을 거부합니다.");
            return false;
        }
    }

    // 명령 전송
    const QByteArray payload = (command + QStringLiteral("\n")).toUtf8();
    if (socket.write(payload) == -1 || !socket.waitForBytesWritten(kWriteTimeoutMs)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Raspberry Pi로 명령을 전송하지 못했습니다.");
        return false;
    }

    // 응답 수신
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
    const QByteArray finalReply = newlineIndex >= 0
                                      ? responseBuffer.left(newlineIndex)
                                      : responseBuffer;

    if (reply)
        *reply = QString::fromUtf8(finalReply).trimmed();
    if (errorMessage)
        errorMessage->clear();
    return true;
}

// ─────────────────────────────────────────────
// PROVISION: Pi 공개키 + TLS 인증서 수신 (TOFU)
// 응답 형식: PROVISION_OK:<pi_pub_b64>:<tls_cert_b64>
// ─────────────────────────────────────────────
bool PiGatewayService::provisionDevice(const QString &userId,
                                       const QString &piHostOrName,
                                       const QString &phonePublicKeyPem,
                                       QString *piPublicKeyPem,
                                       QString *piTlsCertPem,
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

    // PROVISION은 TLS 인증서 없이 연결 (TOFU)
    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage, QString()))
        return false;

    const QString prefix = QStringLiteral("PROVISION_OK:");
    if (!reply.startsWith(prefix)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 공개키 등록에 실패했습니다.\nRaspberry Pi 백엔드 터미널 로그를 확인해주세요.");
        return false;
    }

    // PROVISION_OK:<pi_pub_b64>:<tls_cert_b64>
    const QStringList parts = reply.mid(prefix.size()).split(QLatin1Char(':'));
    if (parts.size() != 2) {
        if (errorMessage)
            *errorMessage = QStringLiteral("PROVISION 응답 형식이 올바르지 않습니다.");
        return false;
    }

    const QByteArray decodedPub  = QByteArray::fromBase64(parts[0].toUtf8());
    const QByteArray decodedCert = QByteArray::fromBase64(parts[1].toUtf8());

    if (decodedPub.isEmpty() || decodedCert.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("PROVISION 응답 디코딩에 실패했습니다.");
        return false;
    }

    if (piPublicKeyPem)
        *piPublicKeyPem = QString::fromUtf8(decodedPub);
    if (piTlsCertPem)
        *piTlsCertPem = QString::fromUtf8(decodedCert);
    if (errorMessage)
        errorMessage->clear();
    return true;
}

// ─────────────────────────────────────────────
// 단방향 인증: 저장된 TLS 인증서로 채널 보호 + nonce 서명 수신
// ─────────────────────────────────────────────
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

    const QString certPath = FileUtils::trustedPiTlsCertPathForUser(trimmedUser);
    const QString command  = QStringLiteral("START_AUTH:%1:%2")
                                 .arg(trimmedUser, QString::fromLatin1(nonce.toBase64()));

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage, certPath))
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

// ─────────────────────────────────────────────
// 키 명령: 저장된 TLS 인증서로 채널 보호
// ─────────────────────────────────────────────
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

    const QString certPath = FileUtils::trustedPiTlsCertPathForUser(trimmedUser);
    const QString command  = QStringLiteral("KEY_COMMAND:%1:%2:%3")
                                 .arg(trimmedUser, trimmedMode, trimmedKey);

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage, certPath))
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


// ─────────────────────────────────────────────
// 회원가입: REGISTER:<user_id>:<pw_b64>:<name_b64>:<email_b64>
// VerifyNone 사용 (등록 전이라 핀닝 불가)
// ─────────────────────────────────────────────
bool PiGatewayService::registerUser(const QString &userId,
                                     const QString &password,
                                     const QString &name,
                                     const QString &email,
                                     const QString &piHostOrName,
                                     QString *errorMessage) const
{
    const QString command = QStringLiteral("REGISTER:%1:%2:%3:%4")
        .arg(userId.trimmed(),
             QString::fromLatin1(password.toUtf8().toBase64()),
             QString::fromLatin1(name.trimmed().toUtf8().toBase64()),
             QString::fromLatin1(email.trimmed().toUtf8().toBase64()));

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))  // VerifyNone
        return false;

    if (reply == QStringLiteral("REGISTER_OK")) {
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage) {
        if (reply.contains(QStringLiteral("ALREADY_EXISTS")))
            *errorMessage = QStringLiteral("이미 사용 중인 아이디입니다.");
        else
            *errorMessage = QStringLiteral("회원가입에 실패했습니다. Pi 서버 응답: ") + reply;
    }
    return false;
}


// ─────────────────────────────────────────────
// 로그인: LOGIN:<user_id>:<pw_b64>
// 핀닝 인증서가 있으면 사용, 없으면 VerifyNone
// ─────────────────────────────────────────────
bool PiGatewayService::loginUser(const QString &userId,
                                  const QString &password,
                                  const QString &piHostOrName,
                                  QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    const QString command     = QStringLiteral("LOGIN:%1:%2")
        .arg(trimmedUser,
             QString::fromLatin1(password.toUtf8().toBase64()));

    // 저장된 TLS 핀닝 인증서가 있으면 사용 (보안 강화), 없으면 VerifyNone
    const QString certPath   = FileUtils::trustedPiTlsCertPathForUser(trimmedUser);
    const QString pinnedPath = QFile::exists(certPath) ? certPath : QString();

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage, pinnedPath))
        return false;

    if (reply == QStringLiteral("LOGIN_OK")) {
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage) {
        if (reply.contains(QStringLiteral("INVALID_CREDENTIALS")))
            *errorMessage = QStringLiteral("아이디 또는 비밀번호가 잘못되었습니다.");
        else
            *errorMessage = QStringLiteral("로그인에 실패했습니다. Pi 서버 응답: ") + reply;
    }
    return false;
}


// ─────────────────────────────────────────────
// 아이디 찾기: FIND_ID:<name_b64>
// 응답: FIND_ID_OK:<user_id>
// ─────────────────────────────────────────────
bool PiGatewayService::findUserId(const QString &name,
                                   const QString &piHostOrName,
                                   QString *foundUserId,
                                   QString *errorMessage) const
{
    const QString command = QStringLiteral("FIND_ID:%1")
        .arg(QString::fromLatin1(name.trimmed().toUtf8().toBase64()));

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))
        return false;

    const QString prefix = QStringLiteral("FIND_ID_OK:");
    if (reply.startsWith(prefix)) {
        if (foundUserId) *foundUserId = reply.mid(prefix.size()).trimmed();
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage) {
        if (reply.contains(QStringLiteral("NOT_FOUND")))
            *errorMessage = QStringLiteral("일치하는 계정을 찾을 수 없습니다.");
        else
            *errorMessage = QStringLiteral("아이디 찾기에 실패했습니다: ") + reply;
    }
    return false;
}


// ─────────────────────────────────────────────
// 비밀번호 찾기 (계정 확인): FIND_PASSWORD:<user_id>:<name_b64>
// 성공 시 ResetPasswordPage로 이동하도록 앱 컨트롤러가 처리
// ─────────────────────────────────────────────
bool PiGatewayService::findPasswordCheck(const QString &userId,
                                          const QString &name,
                                          const QString &piHostOrName,
                                          QString *errorMessage) const
{
    const QString command = QStringLiteral("FIND_PASSWORD:%1:%2")
        .arg(userId.trimmed(),
             QString::fromLatin1(name.trimmed().toUtf8().toBase64()));

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))
        return false;

    if (reply == QStringLiteral("FIND_PASSWORD_OK")) {
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage) {
        if (reply.contains(QStringLiteral("NOT_FOUND")))
            *errorMessage = QStringLiteral("이름과 아이디가 일치하는 계정을 찾을 수 없습니다.");
        else
            *errorMessage = QStringLiteral("계정 확인에 실패했습니다: ") + reply;
    }
    return false;
}


// ─────────────────────────────────────────────
// 비밀번호 재설정: RESET_PASSWORD:<user_id>:<new_pw_b64>
// ─────────────────────────────────────────────
bool PiGatewayService::resetPassword(const QString &userId,
                                      const QString &newPassword,
                                      const QString &piHostOrName,
                                      QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    const QString command     = QStringLiteral("RESET_PASSWORD:%1:%2")
        .arg(trimmedUser,
             QString::fromLatin1(newPassword.toUtf8().toBase64()));

    // 핀닝 인증서가 있으면 사용
    const QString certPath   = FileUtils::trustedPiTlsCertPathForUser(trimmedUser);
    const QString pinnedPath = QFile::exists(certPath) ? certPath : QString();

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage, pinnedPath))
        return false;

    if (reply == QStringLiteral("RESET_PASSWORD_OK")) {
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage) {
        if (reply.contains(QStringLiteral("NOT_FOUND")))
            *errorMessage = QStringLiteral("해당 계정을 찾을 수 없습니다.");
        else
            *errorMessage = QStringLiteral("비밀번호 재설정에 실패했습니다: ") + reply;
    }
    return false;
}
