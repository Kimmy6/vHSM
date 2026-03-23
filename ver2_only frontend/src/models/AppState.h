#ifndef APPSTATE_H
#define APPSTATE_H

#include <QObject>
#include <QString>

class AppState : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString currentUser READ currentUser WRITE setCurrentUser NOTIFY currentUserChanged)
    Q_PROPERTY(QString statusMessage READ statusMessage WRITE setStatusMessage NOTIFY statusMessageChanged)
    Q_PROPERTY(QString operationText READ operationText WRITE setOperationText NOTIFY operationTextChanged)
    Q_PROPERTY(QString selectedFile READ selectedFile WRITE setSelectedFile NOTIFY selectedFileChanged)

public:
    explicit AppState(QObject *parent = nullptr);

    QString currentUser() const;
    QString statusMessage() const;
    QString operationText() const;
    QString selectedFile() const;

    void setCurrentUser(const QString &value);
    void setStatusMessage(const QString &value);
    void setOperationText(const QString &value);
    void setSelectedFile(const QString &value);

signals:
    void currentUserChanged();
    void statusMessageChanged();
    void operationTextChanged();
    void selectedFileChanged();

private:
    QString m_currentUser;
    QString m_statusMessage;
    QString m_operationText;
    QString m_selectedFile;
};

#endif
