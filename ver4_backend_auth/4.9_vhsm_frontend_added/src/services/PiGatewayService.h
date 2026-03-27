#ifndef PIGATEWAYSERVICE_H
#define PIGATEWAYSERVICE_H

#include <QByteArray>
#include <QString>
#include <memory>

class QSslSocket;

class PiGatewayService
{
public:
    PiGatewayService();
    ~PiGatewayService();

    // ── 단발성 커맨드 (인증 전) ─────────────────────────────────────────────
    bool provisionDevice(const QString &userId,
                         const QString &piHostOrName,
                         const QString &phonePublicKeyPem,
                         QString *piPublicKeyPem,
                         QString *piTlsCertPem,
                         QString *errorMessage) const;

    // 세션이 열려 있으면 세션 소켓으로, 없으면 새 TLS 연결로 로그인
    bool loginUser(const QString &userId,
                   const QString &password,
                   const QString &piHostOrName,
                   QString *errorMessage);

    bool registerUser(const QString &userId,
                      const QString &password,
                      const QString &name,
                      const QString &email,
                      const QString &piHostOrName,
                      QString *errorMessage) const;

    bool findUserId(const QString &name,
                    const QString &piHostOrName,
                    QString *foundUserId,
                    QString *errorMessage) const;

    bool findPasswordCheck(const QString &userId,
                           const QString &name,
                           const QString &piHostOrName,
                           QString *errorMessage) const;

    bool resetPassword(const QString &userId,
                       const QString &newPassword,
                       const QString &piHostOrName,
                       QString *errorMessage) const;

    // ── Challenge-Response 인증 → Persistent 세션 수립 ─────────────────────
    // 성공하면 내부 m_session 소켓이 열린 채로 유지됨
    bool startAuthentication(const QString &userId,
                             const QString &piHostOrName,
                             const QByteArray &nonce,
                             QByteArray *piSignature,
                             QString *errorMessage);   // non-const: 소켓 저장

    // ── Persistent 세션 위에서 동작하는 커맨드 ─────────────────────────────
    // data:       암호화 시 평문(Base64), 복호화 시 "<ciphertext_hex>:<iv_hex>"
    // resultData: 암호화 시 "<ciphertext_hex>:<iv_hex>", 복호화 시 평문(Base64)
    bool sendKeyCommand(const QString &userId,
                        const QString &piHostOrName,
                        const QString &mode,
                        const QString &keyNumber,
                        const QString &data,
                        QString *resultData,
                        QString *errorMessage);         // non-const: 세션 소켓 사용

    // 대용량 데이터(이미지 등) 청크 전송용
    bool sendBulkKeyCommand(const QString &userId,
                            const QString &mode,
                            const QString &keyNumber,
                            const QByteArray &payload,
                            QString *resultData,
                            QString *errorMessage);

    // ── 세션 관리 ───────────────────────────────────────────────────────────
    bool hasActiveSession() const;
    void closeSession();    // SESSION_CLOSE 전송 후 소켓 닫기

private:
    // 단발성 TLS 연결 (인증 전 커맨드용)
    bool sendCommand(const QString &host,
                     const QString &command,
                     QString *reply,
                     QString *errorMessage,
                     const QString &pinnedCertPath = QString()) const;

    // Persistent 세션 소켓으로 커맨드 전송
    bool sendSessionCommand(const QString &command,
                            QString *reply,
                            QString *errorMessage);

    // TLS 소켓 설정 헬퍼 (pinning 포함)
    bool configureSslSocket(QSslSocket *socket,
                            const QString &pinnedCertPath,
                            QString *errorMessage) const;

    QSslSocket *m_session   = nullptr;  // persistent 세션 소켓
    QString     m_sessionUser;          // 현재 세션 사용자 ID
};

#endif
