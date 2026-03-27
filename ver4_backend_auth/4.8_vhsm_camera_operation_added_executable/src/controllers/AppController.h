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

    // ── 기존 프로퍼티 ──────────────────────────────────────────────────────
    Q_PROPERTY(QString currentUser             READ currentUser             NOTIFY currentUserChanged)
    Q_PROPERTY(QString statusMessage           READ statusMessage           NOTIFY statusMessageChanged)
    Q_PROPERTY(QString regenerateStatusMessage READ regenerateStatusMessage NOTIFY regenerateStatusMessageChanged)
    Q_PROPERTY(QString operationText           READ operationText           NOTIFY operationTextChanged)
    Q_PROPERTY(QString selectedFile            READ selectedFile            NOTIFY selectedFileChanged)
    Q_PROPERTY(QString connectionPhase         READ connectionPhase         NOTIFY connectionPhaseChanged)
    Q_PROPERTY(QString terminalLog             READ terminalLog             NOTIFY terminalLogChanged)
    Q_PROPERTY(QString latestPublicKey         READ latestPublicKey         NOTIFY latestPublicKeyChanged)

    // ── 인증 관련 신규 프로퍼티 ────────────────────────────────────────────
    Q_PROPERTY(QString signUpStatusMessage       READ signUpStatusMessage       NOTIFY signUpStatusMessageChanged)
    Q_PROPERTY(QString findIdStatusMessage       READ findIdStatusMessage       NOTIFY findIdStatusMessageChanged)
    Q_PROPERTY(QString findPasswordStatusMessage READ findPasswordStatusMessage NOTIFY findPasswordStatusMessageChanged)
    Q_PROPERTY(QString resetPasswordStatusMessage READ resetPasswordStatusMessage NOTIFY resetPasswordStatusMessageChanged)

    // ── TLS 세션 상태 메시지 (ConnectPage 표시용) ──────────────────────────
    Q_PROPERTY(QString tlsSessionStatus          READ tlsSessionStatus          NOTIFY tlsSessionStatusChanged)
    Q_PROPERTY(QString tlsSignaturePreview       READ tlsSignaturePreview       NOTIFY tlsSignaturePreviewChanged)

public:
    explicit AppController(QObject *parent = nullptr);
    ~AppController();

    // 읽기 메서드
    QString currentUser()             const;
    QString statusMessage()           const;
    QString regenerateStatusMessage() const;
    QString operationText()           const;
    QString selectedFile()            const;
    QString connectionPhase()         const;
    QString terminalLog()             const;
    QString latestPublicKey()         const;
    QString signUpStatusMessage()        const;
    QString findIdStatusMessage()        const;
    QString findPasswordStatusMessage()  const;
    QString resetPasswordStatusMessage() const;
    QString tlsSessionStatus()           const;
    QString tlsSignaturePreview()        const;

    // ── 기존 Q_INVOKABLE ──────────────────────────────────────────────────
    Q_INVOKABLE bool connectToHsm(const QString &userId,
                                   const QString &password,
                                   const QString &piHostOrName);

    Q_INVOKABLE void goToRegeneratePage();
    Q_INVOKABLE void goBackToConnectPage();
    Q_INVOKABLE void regeneratePublicKey(const QString &userId, const QString &piHostOrName);
    Q_INVOKABLE void selectFile(const QString &path);
    Q_INVOKABLE void uploadData();
    Q_INVOKABLE void startEncrypt();
    Q_INVOKABLE void startDecrypt();
    Q_INVOKABLE void startEncryptWithKey(const QString &keyNumber);
    Q_INVOKABLE void startDecryptWithKey(const QString &keyNumber);

    // ── 회원가입 / 계정 찾기 ──────────────────────────────────────────────
    Q_INVOKABLE void goToSignUpPage(const QString &piHostOrName = QString());
    Q_INVOKABLE void goToFindIdPage(const QString &piHostOrName = QString());
    Q_INVOKABLE void goToFindPasswordPage();
    Q_INVOKABLE void signUp(const QString &id, const QString &password,
                            const QString &passwordConfirm,
                            const QString &name, const QString &email);
    Q_INVOKABLE void findId(const QString &name);
    Q_INVOKABLE void findPassword(const QString &name, const QString &id);
    Q_INVOKABLE void resetPassword(const QString &password, const QString &passwordConfirm);

    // ── TLS 세션 열기 (신규) ──────────────────────────────────────────────
    // 동작:
    //   키가 없으면 → ML-DSA 키쌍 생성 + Pi TOFU 등록 + Challenge-Response 인증
    //   키가 있으면 → Challenge-Response 인증만 수행
    Q_INVOKABLE void openTlsSession(const QString &userId, const QString &piHostOrName);

signals:
    // 기존 시그널
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

    void signUpStatusMessageChanged();
    void findIdStatusMessageChanged();
    void findPasswordStatusMessageChanged();
    void resetPasswordStatusMessageChanged();

    void openSignUpPage();
    void openFindIdPage();
    void openFindPasswordPage();
    void openResetPasswordPage();

    // TLS 세션 관련 신규 시그널
    void tlsSessionStatusChanged();
    void tlsSignaturePreviewChanged();
    // 성공 시 → Main.qml이 stackView.pop()으로 ConnectPage로 복귀
    void tlsSessionReady();

private:
    void appendTerminalLine(const QString &line);
    void updateConnectionPhase(const QString &phase);

    // ID/PW + ML-DSA 풀 로그인 시퀀스
    void beginConnectionSequence();
    // TLS 세션 전용 시퀀스 (키 생성/등록 + Challenge-Response)
    void beginTlsSessionSequence();

    void finishConnect();
    void finishRegenerate();
    void finishOperation();
    QByteArray generateRandomNonce(int size) const;

    AppState         m_state;
    AuthService      m_authService;
    CryptoService    m_cryptoService;
    PiGatewayService m_piGatewayService;
    MldsaService     m_mldsaService;

    // connectToHsm에서 임시 보관 (beginConnectionSequence 진입 후 즉시 삭제)
    QString m_pendingPassword;
};

#endif
