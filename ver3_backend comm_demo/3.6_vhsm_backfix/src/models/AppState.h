#ifndef APPSTATE_H
#define APPSTATE_H

#include <QObject>
#include <QString>

class AppState : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString currentUser READ currentUser WRITE setCurrentUser NOTIFY currentUserChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage WRITE setStatusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(QString regenerateStatusMessage READ regenerateStatusMessage WRITE setRegenerateStatusMessage NOTIFY regenerateStatusMessageChanged)
    Q_PROPERTY(QString operationText READ operationText WRITE setOperationText NOTIFY operationTextChanged)
    Q_PROPERTY(QString selectedFile READ selectedFile WRITE setSelectedFile NOTIFY selectedFileChanged)
    Q_PROPERTY(QString connectionPhase READ connectionPhase WRITE setConnectionPhase NOTIFY connectionPhaseChanged)
    Q_PROPERTY(QString terminalLog READ terminalLog WRITE setTerminalLog NOTIFY terminalLogChanged)

public:
    explicit AppState(QObject *parent = nullptr);

    QString currentUser() const;
    QString statusMessage() const;
    QString regenerateStatusMessage() const;
    QString operationText() const;
    QString selectedFile() const;
    QString connectionPhase() const;
    QString terminalLog() const;

    void setCurrentUser(const QString &value);
    void setStatusMessage(const QString &value);
    void setRegenerateStatusMessage(const QString &value);
    void setOperationText(const QString &value);
    void setSelectedFile(const QString &value);
    void setConnectionPhase(const QString &value);
    void setTerminalLog(const QString &value);

signals:
    void currentUserChanged();
    void statusMessageChanged();
    void regenerateStatusMessageChanged();
    void operationTextChanged();
    void selectedFileChanged();
    void connectionPhaseChanged();
    void terminalLogChanged();

private:
    QString m_currentUser;
    QString m_statusMessage;
    QString m_regenerateStatusMessage;
    QString m_operationText;
    QString m_selectedFile;
    QString m_connectionPhase;
    QString m_terminalLog;
};

#endif
