#ifndef PIGATEWAYSERVICE_H
#define PIGATEWAYSERVICE_H

#include <QByteArray>
#include <QString>

class PiGatewayService
{
public:
    bool provisionDevice(const QString &userId,
                         const QString &piHostOrName,
                         const QString &phonePublicKeyPem,
                         QString *piPublicKeyPem,
                         QString *errorMessage) const;

    bool startMutualAuthentication(const QString &userId,
                                   const QString &piHostOrName,
                                   const QByteArray &clientChallenge,
                                   QString *sessionId,
                                   QString *piPublicKeyPem,
                                   QByteArray *serverChallenge,
                                   QByteArray *piSignature,
                                   QString *errorMessage) const;

    bool finishMutualAuthentication(const QString &userId,
                                    const QString &piHostOrName,
                                    const QString &sessionId,
                                    const QByteArray &phoneSignature,
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
