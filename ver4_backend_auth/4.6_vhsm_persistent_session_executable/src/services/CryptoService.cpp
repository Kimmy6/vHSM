#include "CryptoService.h"

bool CryptoService::encrypt(const QString &inputPath, QString *message) const
{
    if (inputPath.trimmed().isEmpty()) {
        if (message) *message = "파일을 선택해주세요.";
        return false;
    }
    if (message) *message = "암호화가 완료되었습니다.";
    return true;
}

bool CryptoService::decrypt(const QString &inputPath, QString *message) const
{
    if (inputPath.trimmed().isEmpty()) {
        if (message) *message = "파일을 선택해주세요.";
        return false;
    }
    if (message) *message = "복호화가 완료되었습니다.";
    return true;
}
