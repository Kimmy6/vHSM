#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QFontDatabase>
#include <QStringList>
#include <QDebug>
#include <QFile>

#include "src/controllers/AppController.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    // 앱에 폰트 등록
    const int fontId = QFontDatabase::addApplicationFont(":/assets/fonts/NotoSansKR-Regular.ttf");
    QString appFontFamily = "sans-serif";

    if (fontId != -1) {
        const QStringList families = QFontDatabase::applicationFontFamilies(fontId);
        if (!families.isEmpty()) {
            appFontFamily = families.first();
        }
    } else {
        qWarning() << "Failed to load font from resource";
    }

    QQmlApplicationEngine engine;

    AppController controller;
    engine.rootContext()->setContextProperty("appController", &controller);
    engine.rootContext()->setContextProperty("appFontFamily", appFontFamily);

    qDebug() << "Loaded font family:" << appFontFamily;
    qDebug() << "Check qrc main 1:" << QFile::exists(":/qml/Main.qml");
    qDebug() << "Check qrc font:" << QFile::exists(":/assets/fonts/NotoSansKR-Regular.ttf");

    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);

    engine.load(QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    return app.exec();
}