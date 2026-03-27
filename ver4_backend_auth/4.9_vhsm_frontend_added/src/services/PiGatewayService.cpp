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
#include <QCryptographicHash>

namespace {
constexpr quint16 kPiPort           = 5000;
constexpr int     kConnectTimeoutMs = 5000;
constexpr int     kWriteTimeoutMs   = 3000;
constexpr int     kReadTimeoutMs    = 15000;
}


PiGatewayService::PiGatewayService()  = default;

PiGatewayService::~PiGatewayService()
{
    // 소멸자에서도 세션 정리 (AppController 소멸 시 자동 호출)
    closeSession();
}


// ─────────────────────────────────────────────────────────────────────────────
// TLS 소켓 설정 헬퍼 (pinning 포함)
// pinnedCertPath 비어 있음 → VerifyNone
// pinnedCertPath 있음      → 핀닝 검증
// ─────────────────────────────────────────────────────────────────────────────
bool PiGatewayService::configureSslSocket(QSslSocket *socket,
                                           const QString &pinnedCertPath,
                                           QString *errorMessage) const
{
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setProtocol(QSsl::TlsV1_3OrLater);

    if (pinnedCertPath.isEmpty()) {
        sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
        socket->setSslConfiguration(sslConfig);
        return true;
    }

    QFile certFile(pinnedCertPath);
    if (!certFile.open(QIODevice::ReadOnly)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("저장된 Pi TLS 인증서를 불러오지 못했습니다.\n먼저 'TLS 세션 열기'를 눌러 키를 등록해주세요.");
        return false;
    }
    const QSslCertificate pinnedCert(&certFile, QSsl::Pem);
    certFile.close();

    if (pinnedCert.isNull()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi TLS 인증서가 유효하지 않습니다.");
        return false;
    }

    sslConfig.setCaCertificates({pinnedCert});
    socket->setSslConfiguration(sslConfig);
    socket->setPeerVerifyMode(QSslSocket::VerifyPeer);
    socket->ignoreSslErrors({
        QSslError(QSslError::SelfSignedCertificate, pinnedCert),
        QSslError(QSslError::CertificateUntrusted,  pinnedCert),
        QSslError(QSslError::HostNameMismatch,       pinnedCert),
    });

    // 핑거프린트 저장 (connect 후 검증용)
    socket->setProperty("_pinnedDigest",
        pinnedCert.digest(QCryptographicHash::Sha256));

    return true;
}


// ─────────────────────────────────────────────────────────────────────────────
// 단발성 TLS 연결 헬퍼 (인증 전 커맨드 전용)
// ─────────────────────────────────────────────────────────────────────────────
bool PiGatewayService::sendCommand(const QString &piHostOrName,
                                    const QString &command,
                                    QString *reply,
                                    QString *errorMessage,
                                    const QString &pinnedCertPath) const
{
    const QString trimmedHost = piHostOrName.trimmed();
    if (trimmedHost.isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("Pi IP를 입력해주세요.");
        return false;
    }

    QSslSocket socket;
    if (!configureSslSocket(&socket, pinnedCertPath, errorMessage))
        return false;

    socket.connectToHostEncrypted(trimmedHost, kPiPort);
    if (!socket.waitForEncrypted(kConnectTimeoutMs)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("TLS 연결에 실패했습니다.\n") + socket.errorString();
        return false;
    }

    // 핑거프린트 검증
    const QVariant digest = socket.property("_pinnedDigest");
    if (!digest.isNull()) {
        if (socket.peerCertificate().digest(QCryptographicHash::Sha256) != digest.toByteArray()) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Pi TLS 인증서가 저장된 것과 다릅니다.");
            return false;
        }
    }

    const QByteArray payload = (command + QStringLiteral("\n")).toUtf8();
    if (socket.write(payload) == -1 || !socket.waitForBytesWritten(kWriteTimeoutMs)) {
        if (errorMessage) *errorMessage = QStringLiteral("명령 전송에 실패했습니다.");
        return false;
    }

    QByteArray buf;
    while (true) {
        if (!socket.waitForReadyRead(kReadTimeoutMs)) {
            if (buf.isEmpty()) {
                if (errorMessage) *errorMessage = QStringLiteral("Pi 서버 응답이 없습니다.");
                return false;
            }
            break;
        }
        buf += socket.readAll();
        if (buf.contains('\n')) break;
    }

    const int nl = buf.indexOf('\n');
    if (reply) *reply = QString::fromUtf8(nl >= 0 ? buf.left(nl) : buf).trimmed();
    if (errorMessage) errorMessage->clear();
    return true;
}


// ─────────────────────────────────────────────────────────────────────────────
// Persistent 세션 소켓으로 커맨드 전송
// ─────────────────────────────────────────────────────────────────────────────
bool PiGatewayService::sendSessionCommand(const QString &command,
                                           QString *reply,
                                           QString *errorMessage)
{
    if (!m_session || !m_session->isOpen()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("활성 세션이 없습니다. 다시 인증해주세요.");
        return false;
    }

    const QByteArray payload = (command + QStringLiteral("\n")).toUtf8();
    if (m_session->write(payload) == -1 || !m_session->waitForBytesWritten(kWriteTimeoutMs)) {
        if (errorMessage) *errorMessage = QStringLiteral("세션 명령 전송에 실패했습니다.");
        return false;
    }

    QByteArray buf;
    while (true) {
        if (!m_session->waitForReadyRead(kReadTimeoutMs)) {
            if (buf.isEmpty()) {
                if (errorMessage) *errorMessage = QStringLiteral("세션 응답 대기 시간이 초과되었습니다.");
                return false;
            }
            break;
        }
        buf += m_session->readAll();
        if (buf.contains('\n')) break;
    }

    const int nl = buf.indexOf('\n');
    if (reply) *reply = QString::fromUtf8(nl >= 0 ? buf.left(nl) : buf).trimmed();
    if (errorMessage) errorMessage->clear();
    return true;
}


// ─────────────────────────────────────────────────────────────────────────────
// 세션 관리
// ─────────────────────────────────────────────────────────────────────────────

bool PiGatewayService::hasActiveSession() const
{
    return m_session && m_session->isOpen() && !m_sessionUser.isEmpty();
}

void PiGatewayService::closeSession()
{
    if (!m_session) return;

    if (m_session->isOpen()) {
        // Pi 서버에 정상 종료 알림
        const QString cmd = QStringLiteral("SESSION_CLOSE:") + m_sessionUser;
        m_session->write((cmd + QStringLiteral("\n")).toUtf8());
        m_session->waitForBytesWritten(2000);
        m_session->waitForReadyRead(2000);  // SESSION_CLOSED 응답 대기
        m_session->disconnectFromHost();
        m_session->waitForDisconnected(2000);
    }

    delete m_session;
    m_session = nullptr;
    m_sessionUser.clear();
}


// ─────────────────────────────────────────────────────────────────────────────
// Challenge-Response 인증 → Persistent 세션 수립
// startAuthentication 성공 시 소켓을 닫지 않고 m_session에 보관
// ─────────────────────────────────────────────────────────────────────────────
bool PiGatewayService::startAuthentication(const QString &userId,
                                            const QString &piHostOrName,
                                            const QByteArray &nonce,
                                            QByteArray *piSignature,
                                            QString *errorMessage)
{
    const QString trimmedUser = userId.trimmed();
    const QString trimmedHost = piHostOrName.trimmed();

    if (trimmedUser.isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("유저명을 입력해주세요.");
        return false;
    }
    if (nonce.isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("Nonce 생성에 실패했습니다.");
        return false;
    }

    // 기존 세션이 있으면 먼저 정리
    closeSession();

    // 새 TLS 소켓 생성 (핀닝 적용)
    const QString certPath = FileUtils::trustedPiTlsCertPathForUser(trimmedUser);
    auto *socket = new QSslSocket();
    if (!configureSslSocket(socket, certPath, errorMessage)) {
        delete socket;
        return false;
    }

    socket->connectToHostEncrypted(trimmedHost, kPiPort);
    if (!socket->waitForEncrypted(kConnectTimeoutMs)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("TLS 연결에 실패했습니다.\n") + socket->errorString();
        delete socket;
        return false;
    }

    // 핑거프린트 검증
    const QVariant digest = socket->property("_pinnedDigest");
    if (!digest.isNull()) {
        if (socket->peerCertificate().digest(QCryptographicHash::Sha256) != digest.toByteArray()) {
            if (errorMessage)
                *errorMessage = QStringLiteral("Pi TLS 인증서가 저장된 것과 다릅니다.");
            delete socket;
            return false;
        }
    }

    // START_AUTH 커맨드 전송
    const QString command = QStringLiteral("START_AUTH:%1:%2")
        .arg(trimmedUser, QString::fromLatin1(nonce.toBase64()));
    const QByteArray payload = (command + QStringLiteral("\n")).toUtf8();
    if (socket->write(payload) == -1 || !socket->waitForBytesWritten(kWriteTimeoutMs)) {
        if (errorMessage) *errorMessage = QStringLiteral("인증 요청 전송에 실패했습니다.");
        delete socket;
        return false;
    }

    // AUTH_OK 응답 수신
    QByteArray buf;
    while (true) {
        if (!socket->waitForReadyRead(kReadTimeoutMs)) {
            if (buf.isEmpty()) {
                if (errorMessage) *errorMessage = QStringLiteral("Pi 인증 응답이 없습니다.");
                delete socket;
                return false;
            }
            break;
        }
        buf += socket->readAll();
        if (buf.contains('\n')) break;
    }

    const int nl = buf.indexOf('\n');
    const QString reply = QString::fromUtf8(nl >= 0 ? buf.left(nl) : buf).trimmed();

    const QString prefix = QStringLiteral("AUTH_OK:");
    if (!reply.startsWith(prefix)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Pi 인증에 실패했습니다.\nPi 백엔드 로그를 확인해주세요.");
        delete socket;
        return false;
    }

    const QByteArray sig = QByteArray::fromBase64(reply.mid(prefix.size()).toUtf8());
    if (sig.isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("Pi 서명 디코딩에 실패했습니다.");
        delete socket;
        return false;
    }

    if (piSignature) *piSignature = sig;

    // ── 인증 성공 → 소켓을 닫지 않고 persistent 세션으로 보관 ────────────
    m_session     = socket;
    m_sessionUser = trimmedUser;

    if (errorMessage) errorMessage->clear();
    return true;
}


// ─────────────────────────────────────────────────────────────────────────────
// 키 명령: persistent 세션 소켓 사용
// ─────────────────────────────────────────────────────────────────────────────
bool PiGatewayService::sendKeyCommand(const QString &userId,
                                       const QString &piHostOrName,
                                       const QString &mode,
                                       const QString &keyNumber,
                                       const QString &data,
                                       QString *resultData,
                                       QString *errorMessage)
{
    const QString trimmedUser = userId.trimmed();
    const QString trimmedMode = mode.trimmed().toLower();
    const QString trimmedKey  = keyNumber.trimmed();

    if (trimmedUser.isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("유저명이 비어 있습니다. 다시 로그인해주세요.");
        return false;
    }
    if (trimmedMode != QStringLiteral("encrypt") && trimmedMode != QStringLiteral("decrypt")) {
        if (errorMessage) *errorMessage = QStringLiteral("알 수 없는 명령입니다.");
        return false;
    }
    if (trimmedKey != QStringLiteral("1") && trimmedKey != QStringLiteral("2") && trimmedKey != QStringLiteral("3")) {
        if (errorMessage) *errorMessage = QStringLiteral("키 번호는 1, 2, 3만 사용할 수 있습니다.");
        return false;
    }

    if (!hasActiveSession()) {
        if (errorMessage) *errorMessage = QStringLiteral("세션이 없습니다. 다시 인증해주세요.");
        return false;
    }

    // KEY_COMMAND:<user>:<mode>:<key>:<data>
    const QString command = QStringLiteral("KEY_COMMAND:%1:%2:%3:%4")
        .arg(trimmedUser, trimmedMode, trimmedKey, data.trimmed());

    QString reply;
    if (!sendSessionCommand(command, &reply, errorMessage))
        return false;

    // 암호화 응답: KEY_ENCRYPT_OK:<ciphertext_hex>:<iv_hex>
    if (trimmedMode == QStringLiteral("encrypt") && reply.startsWith(QStringLiteral("KEY_ENCRYPT_OK:"))) {
        if (resultData) *resultData = reply.mid(QString("KEY_ENCRYPT_OK:").length());
        if (errorMessage) errorMessage->clear();
        return true;
    }
    // 복호화 응답: KEY_DECRYPT_OK:<plaintext_b64>
    if (trimmedMode == QStringLiteral("decrypt") && reply.startsWith(QStringLiteral("KEY_DECRYPT_OK:"))) {
        if (resultData) *resultData = reply.mid(QString("KEY_DECRYPT_OK:").length());
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage)
        *errorMessage = reply.isEmpty() ? QStringLiteral("키 명령 처리에 실패했습니다.") : reply;
    return false;
}


// ─────────────────────────────────────────────────────────────────────────────
// 대용량 데이터 청크 전송 (이미지 암복호화용)
// 프로토콜:
//   Qt  →  Pi : KEY_BULK_BEGIN:<user>:<mode>:<key>:<total_bytes>\n
//   Pi  →  Qt : BULK_READY\n
//   Qt  →  Pi : <chunk1_base64>\n  (4096 바이트씩)
//   Pi  →  Qt : CHUNK_OK\n
//   ...반복...
//   Qt  →  Pi : KEY_BULK_END\n
//   Pi  →  Qt : KEY_ENCRYPT_OK:<ct_hex>:<iv_hex>\n
//              또는 KEY_DECRYPT_OK:<plaintext_b64>\n
// ─────────────────────────────────────────────────────────────────────────────
bool PiGatewayService::sendBulkKeyCommand(const QString &userId,
                                           const QString &mode,
                                           const QString &keyNumber,
                                           const QByteArray &payload,
                                           QString *resultData,
                                           QString *errorMessage)
{
    if (!hasActiveSession()) {
        if (errorMessage) *errorMessage = QStringLiteral("활성 세션이 없습니다. 다시 인증해주세요.");
        return false;
    }

    constexpr int kChunkSize = 4096;  // 4KB 청크

    // ── 1. BEGIN 전송 ──────────────────────────────────────────────────────
    const QString beginCmd = QStringLiteral("KEY_BULK_BEGIN:%1:%2:%3:%4\n")
        .arg(userId, mode, keyNumber, QString::number(payload.size()));

    if (m_session->write(beginCmd.toUtf8()) == -1 ||
        !m_session->waitForBytesWritten(kWriteTimeoutMs)) {
        if (errorMessage) *errorMessage = QStringLiteral("BULK BEGIN 전송 실패");
        return false;
    }

    // BULK_READY 대기
    QString reply;
    {
        QByteArray buf;
        while (!buf.contains('\n')) {
            if (!m_session->waitForReadyRead(kReadTimeoutMs)) {
                if (errorMessage) *errorMessage = QStringLiteral("BULK_READY 응답 타임아웃");
                return false;
            }
            buf += m_session->readAll();
        }
        reply = QString::fromUtf8(buf.left(buf.indexOf('\n'))).trimmed();
    }
    if (reply != QStringLiteral("BULK_READY")) {
        if (errorMessage) *errorMessage = QStringLiteral("BULK_READY 수신 실패: ") + reply;
        return false;
    }

    // ── 2. 청크 전송 ──────────────────────────────────────────────────────
    int offset = 0;
    while (offset < payload.size()) {
        const QByteArray chunk      = payload.mid(offset, kChunkSize);
        const QByteArray chunkB64   = chunk.toBase64();
        const QByteArray chunkLine  = chunkB64 + '\n';

        if (m_session->write(chunkLine) == -1 ||
            !m_session->waitForBytesWritten(kWriteTimeoutMs)) {
            if (errorMessage) *errorMessage = QStringLiteral("청크 전송 실패 (offset=%1)").arg(offset);
            return false;
        }

        // CHUNK_OK 대기
        QByteArray buf;
        while (!buf.contains('\n')) {
            if (!m_session->waitForReadyRead(kReadTimeoutMs)) {
                if (errorMessage) *errorMessage = QStringLiteral("CHUNK_OK 응답 타임아웃");
                return false;
            }
            buf += m_session->readAll();
        }
        const QString chunkReply = QString::fromUtf8(buf.left(buf.indexOf('\n'))).trimmed();
        if (chunkReply != QStringLiteral("CHUNK_OK")) {
            if (errorMessage) *errorMessage = QStringLiteral("CHUNK_OK 수신 실패: ") + chunkReply;
            return false;
        }

        offset += kChunkSize;
    }

    // ── 3. END 전송 ───────────────────────────────────────────────────────
    if (m_session->write("KEY_BULK_END\n") == -1 ||
        !m_session->waitForBytesWritten(kWriteTimeoutMs)) {
        if (errorMessage) *errorMessage = QStringLiteral("BULK END 전송 실패");
        return false;
    }

    // ── 4. 최종 결과 수신 ─────────────────────────────────────────────────
    QByteArray buf;
    while (!buf.contains('\n')) {
        if (!m_session->waitForReadyRead(30000)) {  // 암복호화 처리 여유 30초
            if (errorMessage) *errorMessage = QStringLiteral("최종 응답 타임아웃");
            return false;
        }
        buf += m_session->readAll();
    }
    const QString finalReply = QString::fromUtf8(buf.left(buf.indexOf('\n'))).trimmed();

    if (finalReply.startsWith(QStringLiteral("KEY_ENCRYPT_OK:"))) {
        if (resultData) *resultData = finalReply.mid(15); // "KEY_ENCRYPT_OK:" 제거
        if (errorMessage) errorMessage->clear();
        return true;
    }
    if (finalReply.startsWith(QStringLiteral("KEY_DECRYPT_OK:"))) {
        if (resultData) *resultData = finalReply.mid(15);
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage) *errorMessage = finalReply.isEmpty()
        ? QStringLiteral("알 수 없는 응답") : finalReply;
    return false;
}


// ─────────────────────────────────────────────────────────────────────────────
// 단발성 커맨드 구현 (인증 전, 세션 불필요)
// ─────────────────────────────────────────────────────────────────────────────

bool PiGatewayService::provisionDevice(const QString &userId,
                                        const QString &piHostOrName,
                                        const QString &phonePublicKeyPem,
                                        QString *piPublicKeyPem,
                                        QString *piTlsCertPem,
                                        QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    if (trimmedUser.isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("유저명을 입력해주세요.");
        return false;
    }
    if (phonePublicKeyPem.trimmed().isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("스마트폰 공개키를 생성하지 못했습니다.");
        return false;
    }

    const QString command = QStringLiteral("PROVISION_DEVICE:%1:%2")
        .arg(trimmedUser, QString::fromLatin1(phonePublicKeyPem.toUtf8().toBase64()));

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage, QString()))
        return false;

    const QString prefix = QStringLiteral("PROVISION_OK:");
    if (!reply.startsWith(prefix)) {
        if (errorMessage) *errorMessage = QStringLiteral("Pi 공개키 등록에 실패했습니다.");
        return false;
    }

    const QStringList parts = reply.mid(prefix.size()).split(QLatin1Char(':'));
    if (parts.size() != 2) {
        if (errorMessage) *errorMessage = QStringLiteral("PROVISION 응답 형식 오류.");
        return false;
    }

    const QByteArray decodedPub  = QByteArray::fromBase64(parts[0].toUtf8());
    const QByteArray decodedCert = QByteArray::fromBase64(parts[1].toUtf8());
    if (decodedPub.isEmpty() || decodedCert.isEmpty()) {
        if (errorMessage) *errorMessage = QStringLiteral("PROVISION 응답 디코딩 실패.");
        return false;
    }

    if (piPublicKeyPem) *piPublicKeyPem = QString::fromUtf8(decodedPub);
    if (piTlsCertPem)   *piTlsCertPem   = QString::fromUtf8(decodedCert);
    if (errorMessage)   errorMessage->clear();
    return true;
}


bool PiGatewayService::loginUser(const QString &userId,
                                  const QString &password,
                                  const QString &piHostOrName,
                                  QString *errorMessage)
{
    const QString trimmedUser = userId.trimmed();
    const QString command     = QStringLiteral("LOGIN:%1:%2")
        .arg(trimmedUser, QString::fromLatin1(password.toUtf8().toBase64()));

    QString reply;

    // ── 세션이 이미 열려 있으면 세션 소켓으로 전송 (새 연결 시도 금지) ──────
    if (hasActiveSession()) {
        if (!sendSessionCommand(command, &reply, errorMessage))
            return false;
    } else {
        // 세션 없으면 단발성 TLS 연결
        const QString certPath   = FileUtils::trustedPiTlsCertPathForUser(trimmedUser);
        const QString pinnedPath = QFile::exists(certPath) ? certPath : QString();
        if (!sendCommand(piHostOrName, command, &reply, errorMessage, pinnedPath))
            return false;
    }

    if (reply == QStringLiteral("LOGIN_OK")) {
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage)
        *errorMessage = reply.contains(QStringLiteral("INVALID_CREDENTIALS"))
            ? QStringLiteral("아이디 또는 비밀번호가 잘못되었습니다.")
            : QStringLiteral("로그인에 실패했습니다: ") + reply;
    return false;
}


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
    if (!sendCommand(piHostOrName, command, &reply, errorMessage))
        return false;

    if (reply == QStringLiteral("REGISTER_OK")) {
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage)
        *errorMessage = reply.contains(QStringLiteral("ALREADY_EXISTS"))
            ? QStringLiteral("이미 사용 중인 아이디입니다.")
            : QStringLiteral("회원가입에 실패했습니다: ") + reply;
    return false;
}


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

    if (errorMessage)
        *errorMessage = reply.contains(QStringLiteral("NOT_FOUND"))
            ? QStringLiteral("일치하는 계정을 찾을 수 없습니다.")
            : QStringLiteral("아이디 찾기 실패: ") + reply;
    return false;
}


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

    if (errorMessage)
        *errorMessage = reply.contains(QStringLiteral("NOT_FOUND"))
            ? QStringLiteral("이름과 아이디가 일치하는 계정을 찾을 수 없습니다.")
            : QStringLiteral("계정 확인 실패: ") + reply;
    return false;
}


bool PiGatewayService::resetPassword(const QString &userId,
                                      const QString &newPassword,
                                      const QString &piHostOrName,
                                      QString *errorMessage) const
{
    const QString trimmedUser = userId.trimmed();
    const QString command     = QStringLiteral("RESET_PASSWORD:%1:%2")
        .arg(trimmedUser,
             QString::fromLatin1(newPassword.toUtf8().toBase64()));

    const QString certPath   = FileUtils::trustedPiTlsCertPathForUser(trimmedUser);
    const QString pinnedPath = QFile::exists(certPath) ? certPath : QString();

    QString reply;
    if (!sendCommand(piHostOrName, command, &reply, errorMessage, pinnedPath))
        return false;

    if (reply == QStringLiteral("RESET_PASSWORD_OK")) {
        if (errorMessage) errorMessage->clear();
        return true;
    }

    if (errorMessage)
        *errorMessage = reply.contains(QStringLiteral("NOT_FOUND"))
            ? QStringLiteral("해당 계정을 찾을 수 없습니다.")
            : QStringLiteral("비밀번호 재설정 실패: ") + reply;
    return false;
}
