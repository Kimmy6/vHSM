#ifndef APPCONTROLLER_H
#define APPCONTROLLER_H

#pragma once

#include <QObject>
#include <QString>

#include "AppState.h"
#include "AuthService.h"
#include "CryptoService.h"
#include "PiGatewayService.h"
#include "MldsaService.h"

class AppController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString currentUser READ currentUser NOTIFY currentUserChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(QString regenerateStatusMessage READ regenerateStatusMessage NOTIFY regenerateStatusMessageChanged)
    Q_PROPERTY(QString operationText READ operationText NOTIFY operationTextChanged)
    Q_PROPERTY(QString selectedFile READ selectedFile NOTIFY selectedFileChanged)
    Q_PROPERTY(QString connectionPhase READ connectionPhase NOTIFY connectionPhaseChanged)
    Q_PROPERTY(QString terminalLog READ terminalLog NOTIFY terminalLogChanged)
    Q_PROPERTY(QString latestPublicKey READ latestPublicKey NOTIFY latestPublicKeyChanged)

public:
    explicit AppController(QObject *parent = nullptr);

    QString currentUser() const;
    QString statusMessage() const;
    QString regenerateStatusMessage() const;
    QString operationText() const;
    QString selectedFile() const;
    QString connectionPhase() const;
    QString terminalLog() const;
    QString latestPublicKey() const;

    Q_INVOKABLE bool connectToHsm(const QString &userId, const QString &piHostOrName);
    Q_INVOKABLE void goToRegeneratePage();
    Q_INVOKABLE void goBackToConnectPage();
    Q_INVOKABLE void regeneratePublicKey(const QString &userId, const QString &piHostOrName);
    Q_INVOKABLE void selectFile(const QString &path);
    Q_INVOKABLE void uploadData();
    Q_INVOKABLE void startEncrypt();
    Q_INVOKABLE void startDecrypt();
    Q_INVOKABLE void startEncryptWithKey(const QString &keyNumber);
    Q_INVOKABLE void startDecryptWithKey(const QString &keyNumber);

signals:
    void currentUserChanged();
    void statusMessageChanged();
    void regenerateStatusMessageChanged();
    void operationTextChanged();
    void selectedFileChanged();
    void connectionPhaseChanged();
    void terminalLogChanged();
    void latestPublicKeyChanged();

    void connectSuccess();
    void openConnectLoadingPage();
    void openRegeneratePage();
    void backToConnectPage();
    void openActionPage();
    void openWorkLoadingPage();
    void operationFinished();

private:
    void appendTerminalLine(const QString &line);
    void updateConnectionPhase(const QString &phase);
    void beginConnectionSequence();
    void finishConnect();
    void finishRegenerate();
    void finishOperation();
    QByteArray generateRandomNonce(int size) const;

    AppState         m_state;
    AuthService      m_authService;
    CryptoService    m_cryptoService;
    PiGatewayService m_piGatewayService;
    MldsaService     m_mldsaService;
};

#endif
