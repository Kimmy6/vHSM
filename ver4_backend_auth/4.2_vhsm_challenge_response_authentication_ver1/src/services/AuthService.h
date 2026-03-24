#ifndef AUTHSERVICE_H
#define AUTHSERVICE_H

#include <QString>

class AuthService
{
public:
    bool validateUser(const QString &userId) const;
    bool connectUser(const QString &userId) const;
    bool regenerateKey(const QString &userId) const;
};

#endif
