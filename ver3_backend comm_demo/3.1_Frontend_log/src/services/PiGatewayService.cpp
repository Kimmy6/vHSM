#include "PiGatewayService.h"

bool PiGatewayService::requestUserConnectStart(const QString &userId, QString *errorMessage) const
{
    const QString trimmed = userId.trimmed();
    if (trimmed.isEmpty()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("Please enter a user name.");
        return false;
    }

    // TODO: Replace this stub with real Bluetooth/TCP transport to Raspberry Pi.
    // Expected command example: START_USER_CONNECT:<userId>
    if (errorMessage)
        errorMessage->clear();
    return true;
}
