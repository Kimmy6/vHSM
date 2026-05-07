#include "FileUtils.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

namespace {
QString sanitizeUserId(const QString &userId)
{
    QString cleaned;
    cleaned.reserve(userId.size());
    for (const QChar ch : userId) {
        if (ch.isLetterOrNumber() || ch == u'-' || ch == u'_')
            cleaned.append(ch);
    }
    return cleaned.isEmpty() ? QStringLiteral("User") : cleaned;
}

QString appDataDirPath()
{
    QString baseDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (baseDir.isEmpty())
        baseDir = QDir::homePath() + QStringLiteral("/VirtualHSM");

    QDir dir(baseDir);
    dir.mkpath(QStringLiteral("."));
    dir.mkpath(QStringLiteral("public_keys"));
    dir.mkpath(QStringLiteral("private_keys"));
    dir.mkpath(QStringLiteral("trusted_pi_keys"));
    dir.mkpath(QStringLiteral("tls_certs"));
    return baseDir;
}
}

QString FileUtils::displayNameFromPath(const QString &path)
{
    QFileInfo info(path);
    return info.fileName();
}

QString FileUtils::appPublicKeyPathForUser(const QString &userId)
{
    const QDir dir(appDataDirPath() + QStringLiteral("/public_keys"));
    return dir.filePath(sanitizeUserId(userId) + QStringLiteral("_phone_mldsa_public.pem"));
}

QString FileUtils::appPrivateKeyPathForUser(const QString &userId)
{
    const QDir dir(appDataDirPath() + QStringLiteral("/private_keys"));
    return dir.filePath(sanitizeUserId(userId) + QStringLiteral("_phone_mldsa_private.pem"));
}

QString FileUtils::trustedPiPublicKeyPathForUser(const QString &userId)
{
    const QDir dir(appDataDirPath() + QStringLiteral("/trusted_pi_keys"));
    return dir.filePath(sanitizeUserId(userId) + QStringLiteral("_pi_mldsa_public.pem"));
}

QString FileUtils::trustedPiTlsCertPathForUser(const QString &userId)
{
    const QDir dir(appDataDirPath() + QStringLiteral("/tls_certs"));
    return dir.filePath(sanitizeUserId(userId) + QStringLiteral("_pi_tls_cert.pem"));
}

bool FileUtils::writeTextFile(const QString &path, const QString &data, QString *errorMessage)
{
    QFileInfo info(path);
    QDir().mkpath(info.dir().absolutePath());

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("파일을 저장할 수 없습니다.").arg(path);
        return false;
    }

    const QByteArray bytes = data.toUtf8();
    if (file.write(bytes) != bytes.size()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("파일 쓰기에 실패했습니다.").arg(path);
        return false;
    }

    if (errorMessage)
        errorMessage->clear();
    return true;
}

QString FileUtils::readTextFile(const QString &path, QString *errorMessage)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("입력하신 IP 주소를 찾을 수 없습니다.\nTailscale 로그인 상태 및 백엔드 구동 여부를 확인해주세요.").arg(path);
        return QString();
    }

    if (errorMessage)
        errorMessage->clear();
    return QString::fromUtf8(file.readAll());
}
