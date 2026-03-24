#ifndef PIGATEWAYSERVICE_H
#define PIGATEWAYSERVICE_H

#include <QByteArray>
#include <QString>

class PiGatewayService
{
public:
    // 초기 1회: Pi 공개키 + TLS 인증서를 앱에 등록 (TOFU)
    // 첫 연결은 TLS VerifyNone → 인증서를 받아 저장 → 이후 핀닝
    bool provisionDevice(const QString &userId,
                         const QString &piHostOrName,
                         const QString &phonePublicKeyPem,
                         QString *piPublicKeyPem,
                         QString *piTlsCertPem,   // [NEW] TLS 인증서도 함께 수신
                         QString *errorMessage) const;

    // 단방향 인증: 저장된 TLS 인증서로 핀닝 후 nonce 서명 검증
    bool startAuthentication(const QString &userId,
                             const QString &piHostOrName,
                             const QByteArray &nonce,
                             QByteArray *piSignature,
                             QString *errorMessage) const;

    bool sendKeyCommand(const QString &userId,
                        const QString &piHostOrName,
                        const QString &mode,
                        const QString &keyNumber,
                        QString *errorMessage) const;

private:
    // pinnedCertPath 가 비어 있으면 VerifyNone (PROVISION 전용)
    // 비어 있지 않으면 해당 인증서로 핀닝 검증
    bool sendCommand(const QString &host,
                     const QString &command,
                     QString *reply,
                     QString *errorMessage,
                     const QString &pinnedCertPath = QString()) const;
};

#endif
