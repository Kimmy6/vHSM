#ifndef AUTHSERVICE_H
#define AUTHSERVICE_H

#include <QString>

class AuthService
{
public:
    // 기존: userId 공백 여부 확인
    bool validateUser(const QString &userId) const;
    bool connectUser(const QString &userId) const;
    bool regenerateKey(const QString &userId) const;

    // 신규: 비밀번호 유효성 검사 (8자 이상, 영문+숫자 포함)
    bool validatePassword(const QString &password, QString *errorMessage = nullptr) const;

    // 신규: 비밀번호 일치 여부 확인
    bool passwordsMatch(const QString &password,
                        const QString &passwordConfirm,
                        QString *errorMessage = nullptr) const;

    // 신규: 이메일 형식 확인
    bool validateEmail(const QString &email, QString *errorMessage = nullptr) const;
};

#endif
