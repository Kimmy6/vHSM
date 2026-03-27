#ifndef CRYPTOSERVICE_H
#define CRYPTOSERVICE_H

#include <QString>

class CryptoService
{
public:
    bool encrypt(const QString &inputPath, QString *message = nullptr) const;
    bool decrypt(const QString &inputPath, QString *message = nullptr) const;
};

#endif
