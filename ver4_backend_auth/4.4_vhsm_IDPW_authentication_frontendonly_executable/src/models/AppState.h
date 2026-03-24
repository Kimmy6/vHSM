#ifndef APPSTATE_H
#define APPSTATE_H

#include <QObject>
#include <QString>

class AppState : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString currentUser READ currentUser WRITE setCurrentUser NOTIFY currentUserChanged)
    Q_PROPERTY(QString currentPiHost READ currentPiHost WRITE setCurrentPiHost NOTIFY currentPiHostChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage WRITE setStatusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(QString regenerateStatusMessage READ regenerateStatusMessage WRITE setRegenerateStatusMessage NOTIFY regenerateStatusMessageChanged)
    Q_PROPERTY(QString operationText READ operationText WRITE setOperationText NOTIFY operationTextChanged)
    Q_PROPERTY(QString selectedFile READ selectedFile WRITE setSelectedFile NOTIFY selectedFileChanged)
    Q_PROPERTY(QString connectionPhase READ connectionPhase WRITE setConnectionPhase NOTIFY connectionPhaseChanged)
    Q_PROPERTY(QString terminalLog READ terminalLog WRITE setTerminalLog NOTIFY terminalLogChanged)
    Q_PROPERTY(QString latestPublicKey READ latestPublicKey WRITE setLatestPublicKey NOTIFY latestPublicKeyChanged)
    Q_PROPERTY(QString signUpStatusMessage READ signUpStatusMessage WRITE setSignUpStatusMessage NOTIFY signUpStatusMessageChanged)
    Q_PROPERTY(QString findIdStatusMessage READ findIdStatusMessage WRITE setFindIdStatusMessage NOTIFY findIdStatusMessageChanged)
    Q_PROPERTY(QString findPasswordStatusMessage READ findPasswordStatusMessage WRITE setFindPasswordStatusMessage NOTIFY findPasswordStatusMessageChanged)
    Q_PROPERTY(QString resetPasswordStatusMessage READ resetPasswordStatusMessage WRITE setResetPasswordStatusMessage NOTIFY resetPasswordStatusMessageChanged)

public:
    explicit AppState(QObject *parent = nullptr);

    QString currentUser() const;
    void setCurrentUser(const QString &value);

    QString currentPiHost() const;
    void setCurrentPiHost(const QString &value);

    QString statusMessage() const;
    void setStatusMessage(const QString &value);

    QString regenerateStatusMessage() const;
    void setRegenerateStatusMessage(const QString &value);

    QString operationText() const;
    void setOperationText(const QString &value);

    QString selectedFile() const;
    void setSelectedFile(const QString &value);

    QString connectionPhase() const;
    void setConnectionPhase(const QString &value);

    QString terminalLog() const;
    void setTerminalLog(const QString &value);

    QString latestPublicKey() const;
    void setLatestPublicKey(const QString &value);

    QString signUpStatusMessage() const;
    void setSignUpStatusMessage(const QString &value);

    QString findIdStatusMessage() const;
    void setFindIdStatusMessage(const QString &value);

    QString findPasswordStatusMessage() const;
    void setFindPasswordStatusMessage(const QString &value);

    QString resetPasswordStatusMessage() const;
    void setResetPasswordStatusMessage(const QString &value);

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
};

#endif
