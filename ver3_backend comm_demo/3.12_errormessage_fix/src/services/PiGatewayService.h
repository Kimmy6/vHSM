#pragma once

#include <QString>

class PiGatewayService
{
public:
    bool requestUserConnectStart(const QString &userId,
                                 const QString &piHostOrName,
                                 QString *errorMessage) const;

    bool finishMutualAuth(const QString &userId,
                          const QString &piHostOrName,
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