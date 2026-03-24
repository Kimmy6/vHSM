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

bool AuthService::validatePassword(const QString &password, QString *errorMessage) const
{
    if (password.length() < 8) {
        if (errorMessage) *errorMessage = QStringLiteral("비밀번호는 8자 이상이어야 합니다.");
        return false;
    }

    bool hasLetter = false;
    bool hasDigit  = false;
    for (const QChar &ch : password) {
        if (ch.isLetter()) hasLetter = true;
        if (ch.isDigit())  hasDigit  = true;
        if (hasLetter && hasDigit) break;
    }

    if (!hasLetter || !hasDigit) {
        if (errorMessage) *errorMessage = QStringLiteral("비밀번호에 영문자와 숫자를 모두 포함해야 합니다.");
        return false;
    }

    if (errorMessage) errorMessage->clear();
    return true;
}

bool AuthService::passwordsMatch(const QString &password,
                                  const QString &passwordConfirm,
                                  QString *errorMessage) const
{
    if (password != passwordConfirm) {
        if (errorMessage) *errorMessage = QStringLiteral("비밀번호가 일치하지 않습니다.");
        return false;
    }
    if (errorMessage) errorMessage->clear();
    return true;
}

bool AuthService::validateEmail(const QString &email, QString *errorMessage) const
{
    const QString trimmed = email.trimmed();
    // 간단한 형식 검사: @ 포함 + @ 앞뒤에 문자 존재
    const int atPos = trimmed.indexOf(QLatin1Char('@'));
    if (atPos <= 0 || atPos >= trimmed.length() - 2) {
        if (errorMessage) *errorMessage = QStringLiteral("올바른 이메일 형식을 입력해주세요.");
        return false;
    }
    if (errorMessage) errorMessage->clear();
    return true;
}
