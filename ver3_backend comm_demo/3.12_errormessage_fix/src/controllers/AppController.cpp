#pragma once

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

signals:
    void currentUserChanged();
    void currentPiHostChanged();
    void statusMessageChanged();
    void regenerateStatusMessageChanged();
    void operationTextChanged();

private:
    QString m_currentUser;
    QString m_currentPiHost;
    QString m_statusMessage;
    QString m_regenerateStatusMessage;
    QString m_operationText;
};