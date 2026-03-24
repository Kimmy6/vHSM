#ifndef PIGATEWAYSERVICE_H
#define PIGATEWAYSERVICE_H

#include <QByteArray>
#include <QString>

class PiGatewayService
{
public:
    // ── 기존 메서드 ──────────────────────────────────────────────────────────

    // 초기 1회: Pi 공개키 + TLS 인증서 등록 (TOFU)
    bool provisionDevice(const QString &userId,
                         const QString &piHostOrName,
                         const QString &phonePublicKeyPem,
                         QString *piPublicKeyPem,
                         QString *piTlsCertPem,
                         QString *errorMessage) const;

    // 단방향 ML-DSA 인증
    bool startAuthentication(const QString &userId,
                             const QString &piHostOrName,
                             const QByteArray &nonce,
                             QByteArray *piSignature,
                             QString *errorMessage) const;

    // Arduino 키 명령
    bool sendKeyCommand(const QString &userId,
                        const QString &piHostOrName,
                        const QString &mode,
                        const QString &keyNumber,
                        QString *errorMessage) const;

    // ── 신규: ID/PW 인증 메서드 ──────────────────────────────────────────────

    // 회원가입 — REGISTER 커맨드
    bool registerUser(const QString &userId,
                      const QString &password,
                      const QString &name,
                      const QString &email,
                      const QString &piHostOrName,
                      QString *errorMessage) const;

    // 로그인 (ID/PW 검증) — LOGIN 커맨드
    // connectToHsm의 첫 번째 단계로 호출됨
    bool loginUser(const QString &userId,
                   const QString &password,
                   const QString &piHostOrName,
                   QString *errorMessage) const;

    // 아이디 찾기 — FIND_ID 커맨드
    bool findUserId(const QString &name,
                    const QString &piHostOrName,
                    QString *foundUserId,
                    QString *errorMessage) const;

    // 비밀번호 찾기 (이름+ID 일치 확인) — FIND_PASSWORD 커맨드
    bool findPasswordCheck(const QString &userId,
                           const QString &name,
                           const QString &piHostOrName,
                           QString *errorMessage) const;

    // 비밀번호 재설정 — RESET_PASSWORD 커맨드
    bool resetPassword(const QString &userId,
                       const QString &newPassword,
                       const QString &piHostOrName,
                       QString *errorMessage) const;

private:
    // pinnedCertPath가 비어 있으면 VerifyNone (PROVISION/사용자 관리 전용)
    // 비어 있지 않으면 해당 인증서로 핀닝 검증 (ML-DSA 인증/키 명령)
    bool sendCommand(const QString &host,
                     const QString &command,
                     QString *reply,
                     QString *errorMessage,
                     const QString &pinnedCertPath = QString()) const;
};

#endif
