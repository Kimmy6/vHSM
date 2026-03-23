#ifndef APPCONTROLLER_H
#define APPCONTROLLER_H

#pragma once

#include <QObject>
#include <QTimer>
#include "AppState.h"
#include "AuthService.h"
#include "CryptoService.h"

class AppController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString currentUser READ currentUser NOTIFY currentUserChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(QString operationText READ operationText NOTIFY operationTextChanged)
    Q_PROPERTY(QString selectedFile READ selectedFile NOTIFY selectedFileChanged)

public:
    explicit AppController(QObject *parent = nullptr);

    QString currentUser() const;
    QString statusMessage() const;
    QString operationText() const;
    QString selectedFile() const;

    Q_INVOKABLE void connectToHsm(const QString &userId);
    Q_INVOKABLE void goToRegeneratePage();
    Q_INVOKABLE void regeneratePublicKey(const QString &userId);
    Q_INVOKABLE void selectFile(const QString &path);
    Q_INVOKABLE void uploadData();
    Q_INVOKABLE void startEncrypt();
    Q_INVOKABLE void startDecrypt();

signals:
    void currentUserChanged();
    void statusMessageChanged();
    void operationTextChanged();
    void selectedFileChanged();

    void connectSuccess();
    void openRegeneratePage();
    void backToConnectPage();
    void openActionPage();
    void openWorkLoadingPage();
    void operationFinished();

private:
    void syncSignals();
    void finishConnect();
    void finishOperation();

    AppState m_state;
    AuthService m_authService;
    CryptoService m_cryptoService;
    QString m_pendingResult;
};

#endif
