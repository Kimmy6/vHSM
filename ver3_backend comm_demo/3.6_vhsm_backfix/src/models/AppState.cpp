#include "AppState.h"

AppState::AppState(QObject *parent) : QObject(parent), m_operationText("Working...") {}
QString AppState::currentUser() const { return m_currentUser; }
QString AppState::statusMessage() const { return m_statusMessage; }
QString AppState::regenerateStatusMessage() const { return m_regenerateStatusMessage; }
QString AppState::operationText() const { return m_operationText; }
QString AppState::selectedFile() const { return m_selectedFile; }
QString AppState::connectionPhase() const { return m_connectionPhase; }
QString AppState::terminalLog() const { return m_terminalLog; }
void AppState::setCurrentUser(const QString &value) { if (m_currentUser == value) return; m_currentUser = value; emit currentUserChanged(); }
void AppState::setStatusMessage(const QString &value) { if (m_statusMessage == value) return; m_statusMessage = value; emit statusMessageChanged(); }
void AppState::setRegenerateStatusMessage(const QString &value) { if (m_regenerateStatusMessage == value) return; m_regenerateStatusMessage = value; emit regenerateStatusMessageChanged(); }
void AppState::setOperationText(const QString &value) { if (m_operationText == value) return; m_operationText = value; emit operationTextChanged(); }
void AppState::setSelectedFile(const QString &value) { if (m_selectedFile == value) return; m_selectedFile = value; emit selectedFileChanged(); }
void AppState::setConnectionPhase(const QString &value) { if (m_connectionPhase == value) return; m_connectionPhase = value; emit connectionPhaseChanged(); }
void AppState::setTerminalLog(const QString &value) { if (m_terminalLog == value) return; m_terminalLog = value; emit terminalLogChanged(); }
