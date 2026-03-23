#include "FileUtils.h"
#include <QFileInfo>

QString FileUtils::displayNameFromPath(const QString &path)
{
    QFileInfo info(path);
    return info.fileName();
}
