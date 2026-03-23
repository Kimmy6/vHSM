#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include "src/controllers/AppController.h"

#include <QDebug>
#include <QFile>

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    QQmlApplicationEngine engine;

    AppController controller;
    engine.rootContext()->setContextProperty("appController", &controller);

    const QUrl url(QStringLiteral("qrc:/qml/Main.qml"));
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);
    
    qDebug() << "Check qrc main 1:" << QFile::exists(":/qml/Main.qml");
    qDebug() << "Check qrc main 2:" << QFile::exists(":/Main.qml");

    engine.load(QUrl(QStringLiteral("qrc:/qml/Main.qml")));
    return app.exec();
}
