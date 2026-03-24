#include "AppState.h"

AppState::AppState(QObject *parent)
    : QObject(parent),
      m_operationText(QStringLiteral("Working..."))
{
}

QString AppState::currentUser() const { return m_currentUser; }
QString AppState::currentPiHost() const { return m_currentPiHost; }
QString AppState::statusMessage() const { return m_statusMessage; }
QString AppState::regenerateStatusMessage() const { return m_regenerateStatusMessage; }
QString AppState::operationText() const { return m_operationText; }
QString AppState::selectedFile() const { return m_selectedFile; }
QString AppState::connectionPhase() const { return m_connectionPhase; }
QString AppState::terminalLog() const { return m_terminalLog; }
QString AppState::latestPublicKey() const { return m_latestPublicKey; }

void AppState::setCurrentUser(const QString &value)
{
    if (m_currentUser == value)
        return;
    m_currentUser = value;
    emit currentUserChanged();
}

void AppState::setCurrentPiHost(const QString &value)
{
    if (m_currentPiHost == value)
        return;
    m_currentPiHost = value;
    emit currentPiHostChanged();
}

void AppState::setStatusMessage(const QString &value)
{
    if (m_statusMessage == value)
        return;
    m_statusMessage = value;
    emit statusMessageChanged();
}

void AppState::setRegenerateStatusMessage(const QString &value)
{
    if (m_regenerateStatusMessage == value)
        return;
    m_regenerateStatusMessage = value;
    emit regenerateStatusMessageChanged();
}

void AppState::setOperationText(const QString &value)
{
    if (m_operationText == value)
        return;
    m_operationText = value;
    emit operationTextChanged();
}

void AppState::setSelectedFile(const QString &value)
{
    if (m_selectedFile == value)
        return;
    m_selectedFile = value;
    emit selectedFileChanged();
}

void AppState::setConnectionPhase(const QString &value)
{
    if (m_connectionPhase == value)
        return;
    m_connectionPhase = value;
    emit connectionPhaseChanged();
}

void AppState::setTerminalLog(const QString &value)
{
    if (m_terminalLog == value)
        return;
    m_terminalLog = value;
    emit terminalLogChanged();
}

void AppState::setLatestPublicKey(const QString &value)
{
    if (m_latestPublicKey == value)
        return;
    m_latestPublicKey = value;
    emit latestPublicKeyChanged();
}

QString AppState::signUpStatusMessage() const { return m_signUpStatusMessage; }
void AppState::setSignUpStatusMessage(const QString &value) {
    if (m_signUpStatusMessage == value) return;
    m_signUpStatusMessage = value;
    emit signUpStatusMessageChanged();
}

QString AppState::findIdStatusMessage() const { return m_findIdStatusMessage; }
void AppState::setFindIdStatusMessage(const QString &value) {
    if (m_findIdStatusMessage == value) return;
    m_findIdStatusMessage = value;
    emit findIdStatusMessageChanged();
}

QString AppState::findPasswordStatusMessage() const { return m_findPasswordStatusMessage; }
void AppState::setFindPasswordStatusMessage(const QString &value) {
    if (m_findPasswordStatusMessage == value) return;
    m_findPasswordStatusMessage = value;
    emit findPasswordStatusMessageChanged();
}

QString AppState::resetPasswordStatusMessage() const { return m_resetPasswordStatusMessage; }
void AppState::setResetPasswordStatusMessage(const QString &value) {
    if (m_resetPasswordStatusMessage == value) return;
    m_resetPasswordStatusMessage = value;
    emit resetPasswordStatusMessageChanged();
}
