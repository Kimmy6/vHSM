#ifndef MLDSASERVICE_H
#define MLDSASERVICE_H

#include <QByteArray>
#include <QString>

class MldsaService
{
public:
    bool generateDeviceKeyPair(const QString &privateKeyPath,
                               const QString &publicKeyPath,
                               QString *publicKeyPem = nullptr,
                               QString *errorMessage = nullptr) const;

    bool signMessage(const QString &privateKeyPem,
                     const QByteArray &message,
                     QByteArray *signature,
                     QString *errorMessage = nullptr) const;

    bool verifyMessage(const QString &publicKeyPem,
                       const QByteArray &message,
                       const QByteArray &signature,
                       QString *errorMessage = nullptr) const;
};

#endif
