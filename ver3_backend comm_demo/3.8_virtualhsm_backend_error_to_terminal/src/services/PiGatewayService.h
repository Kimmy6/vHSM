#ifndef PIGATEWAYSERVICE_H
#define PIGATEWAYSERVICE_H

#include <QString>

class PiGatewayService
{
public:
    bool authenticateUser(const QString &userId,
                          const QString &piHostOrName,
                          QString *errorMessage = nullptr) const;

    bool regeneratePublicKey(const QString &userId,
                             const QString &piHostOrName,
                             QString *publicKeyPem = nullptr,
                             QString *errorMessage = nullptr) const;

private:
    bool sendCommand(const QString &piHostOrName,
                     const QString &command,
                     QString *reply,
                     QString *errorMessage) const;
};

#endif
