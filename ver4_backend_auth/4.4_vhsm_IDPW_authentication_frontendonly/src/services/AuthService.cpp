#include "AuthService.h"

bool AuthService::validateUser(const QString &userId) const
{
    return !userId.trimmed().isEmpty();
}

bool AuthService::connectUser(const QString &userId) const
{
    return validateUser(userId);
}

bool AuthService::regenerateKey(const QString &userId) const
{
    return validateUser(userId);
}
