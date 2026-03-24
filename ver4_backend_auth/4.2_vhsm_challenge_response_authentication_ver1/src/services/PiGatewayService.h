#ifndef PIGATEWAYSERVICE_H
#define PIGATEWAYSERVICE_H

#include <QByteArray>
#include <QString>

class PiGatewayService
{
public:
    // 초기 1회: Pi 공개키를 앱에 등록
    bool provisionDevice(const QString &userId,
                         const QString &piHostOrName,
                         const QString &phonePublicKeyPem,
                         QString *piPublicKeyPem,
                         QString *errorMessage) const;

    // 단방향 인증: 앱이 nonce를 보내면 Pi가 서명해서 반환
    // 프로토콜: START_AUTH:<userId>:<nonce_b64> → AUTH_OK:<pi_sig_b64>
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
    bool sendCommand(const QString &host,
                     const QString &command,
                     QString *reply,
                     QString *errorMessage) const;
};

#endif
