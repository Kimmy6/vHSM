#ifndef APPSTATE_H
#define APPSTATE_H

#include <QObject>
#include <QString>

class AppState : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString currentUser               READ currentUser               WRITE setCurrentUser               NOTIFY currentUserChanged)
    Q_PROPERTY(QString currentPiHost             READ currentPiHost             WRITE setCurrentPiHost             NOTIFY currentPiHostChanged)
    Q_PROPERTY(QString statusMessage             READ statusMessage             WRITE setStatusMessage             NOTIFY statusMessageChanged)
    Q_PROPERTY(QString regenerateStatusMessage   READ regenerateStatusMessage   WRITE setRegenerateStatusMessage   NOTIFY regenerateStatusMessageChanged)
    Q_PROPERTY(QString operationText             READ operationText             WRITE setOperationText             NOTIFY operationTextChanged)
    Q_PROPERTY(QString selectedFile              READ selectedFile              WRITE setSelectedFile              NOTIFY selectedFileChanged)
    Q_PROPERTY(QString connectionPhase           READ connectionPhase           WRITE setConnectionPhase           NOTIFY connectionPhaseChanged)
    Q_PROPERTY(QString terminalLog               READ terminalLog               WRITE setTerminalLog               NOTIFY terminalLogChanged)
    Q_PROPERTY(QString latestPublicKey           READ latestPublicKey           WRITE setLatestPublicKey           NOTIFY latestPublicKeyChanged)
    Q_PROPERTY(QString signUpStatusMessage       READ signUpStatusMessage       WRITE setSignUpStatusMessage       NOTIFY signUpStatusMessageChanged)
    Q_PROPERTY(QString findIdStatusMessage       READ findIdStatusMessage       WRITE setFindIdStatusMessage       NOTIFY findIdStatusMessageChanged)
    Q_PROPERTY(QString findPasswordStatusMessage READ findPasswordStatusMessage WRITE setFindPasswordStatusMessage NOTIFY findPasswordStatusMessageChanged)
    Q_PROPERTY(QString resetPasswordStatusMessage READ resetPasswordStatusMessage WRITE setResetPasswordStatusMessage NOTIFY resetPasswordStatusMessageChanged)
    Q_PROPERTY(QString pendingResetUserId        READ pendingResetUserId        WRITE setPendingResetUserId        NOTIFY pendingResetUserIdChanged)
    // TLS 세션 열기 결과 메시지 (ConnectPage에 표시)
    Q_PROPERTY(QString tlsSessionStatus          READ tlsSessionStatus          WRITE setTlsSessionStatus          NOTIFY tlsSessionStatusChanged)

public:
    explicit AppState(QObject *parent = nullptr);

    QString currentUser()               const;  void setCurrentUser(const QString &v);
    QString currentPiHost()             const;  void setCurrentPiHost(const QString &v);
    QString statusMessage()             const;  void setStatusMessage(const QString &v);
    QString regenerateStatusMessage()   const;  void setRegenerateStatusMessage(const QString &v);
    QString operationText()             const;  void setOperationText(const QString &v);
    QString selectedFile()              const;  void setSelectedFile(const QString &v);
    QString connectionPhase()           const;  void setConnectionPhase(const QString &v);
    QString terminalLog()               const;  void setTerminalLog(const QString &v);
    QString latestPublicKey()           const;  void setLatestPublicKey(const QString &v);
    QString signUpStatusMessage()       const;  void setSignUpStatusMessage(const QString &v);
    QString findIdStatusMessage()       const;  void setFindIdStatusMessage(const QString &v);
    QString findPasswordStatusMessage() const;  void setFindPasswordStatusMessage(const QString &v);
    QString resetPasswordStatusMessage()const;  void setResetPasswordStatusMessage(const QString &v);
    QString pendingResetUserId()        const;  void setPendingResetUserId(const QString &v);
    QString tlsSessionStatus()          const;  void setTlsSessionStatus(const QString &v);

signals:
    void currentUserChanged();
    void currentPiHostChanged();
    void statusMessageChanged();
    void regenerateStatusMessageChanged();
    void operationTextChanged();
    void selectedFileChanged();
    void connectionPhaseChanged();
    void terminalLogChanged();
    void latestPublicKeyChanged();
    void signUpStatusMessageChanged();
    void findIdStatusMessageChanged();
    void findPasswordStatusMessageChanged();
    void resetPasswordStatusMessageChanged();
    void pendingResetUserIdChanged();
    void tlsSessionStatusChanged();

private:
    QString m_currentUser;
    QString m_currentPiHost;
    QString m_statusMessage;
    QString m_regenerateStatusMessage;
    QString m_operationText;
    QString m_selectedFile;
    QString m_connectionPhase;
    QString m_terminalLog;
    QString m_latestPublicKey;
    QString m_signUpStatusMessage;
    QString m_findIdStatusMessage;
    QString m_findPasswordStatusMessage;
    QString m_resetPasswordStatusMessage;
    QString m_pendingResetUserId;
    QString m_tlsSessionStatus;
};

#endif
