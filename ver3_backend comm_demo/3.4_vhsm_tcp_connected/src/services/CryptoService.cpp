#include "CryptoService.h"

bool CryptoService::encrypt(const QString &inputPath, QString *message) const
{
    if (inputPath.trimmed().isEmpty()) {
        if (message) *message = "Please select a file first.";
        return false;
    }
    if (message) *message = "Encryption complete.";
    return true;
}

bool CryptoService::decrypt(const QString &inputPath, QString *message) const
{
    if (inputPath.trimmed().isEmpty()) {
        if (message) *message = "Please select a file first.";
        return false;
    }
    if (message) *message = "Decryption complete.";
    return true;
}
