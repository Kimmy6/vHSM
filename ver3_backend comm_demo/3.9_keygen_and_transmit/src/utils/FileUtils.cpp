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
    return dir.filePath(QStringLiteral("public_keys"));
}
}

QString FileUtils::displayNameFromPath(const QString &path)
{
    QFileInfo info(path);
    return info.fileName();
}

QString FileUtils::appPublicKeyPathForUser(const QString &userId)
{
    const QDir dir(appDataDirPath());
    return dir.filePath(sanitizeUserId(userId) + QStringLiteral("_mldsa_public.pem"));
}

bool FileUtils::writeTextFile(const QString &path, const QString &data, QString *errorMessage)
{
    QFileInfo info(path);
    QDir().mkpath(info.dir().absolutePath());

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        if (errorMessage)
            *errorMessage = QStringLiteral("파일을 저장할 수 없습니다: %1").arg(path);
        return false;
    }

    const QByteArray bytes = data.toUtf8();
    if (file.write(bytes) != bytes.size()) {
        if (errorMessage)
            *errorMessage = QStringLiteral("파일 쓰기에 실패했습니다: %1").arg(path);
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
            *errorMessage = QStringLiteral("저장된 공개키 파일을 열 수 없습니다: %1").arg(path);
        return QString();
    }

    if (errorMessage)
        errorMessage->clear();
    return QString::fromUtf8(file.readAll());
}
