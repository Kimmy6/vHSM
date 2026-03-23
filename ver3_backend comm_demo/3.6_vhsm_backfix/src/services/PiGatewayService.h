#ifndef PIGATEWAYSERVICE_H
#define PIGATEWAYSERVICE_H

#include <QString>

class PiGatewayService
{
public:
    bool requestUserConnectStart(const QString &userId,
                                 const QString &piHostOrName,
                                 QString *errorMessage = nullptr) const;
};

#endif
