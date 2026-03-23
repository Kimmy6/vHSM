#ifndef FILEUTILS_H
#define FILEUTILS_H

#include <QString>

class FileUtils
{
public:
    static QString displayNameFromPath(const QString &path);
    static QString appPublicKeyPathForUser(const QString &userId);
    static bool writeTextFile(const QString &path, const QString &data, QString *errorMessage = nullptr);
    static QString readTextFile(const QString &path, QString *errorMessage = nullptr);
};

#endif
