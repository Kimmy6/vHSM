#include "AppState.h"

AppState::AppState(QObject *parent) : QObject(parent), m_operationText("Working...") {}
QString AppState::currentUser() const { return m_currentUser; }
QString AppState::statusMessage() const { return m_statusMessage; }
QString AppState::operationText() const { return m_operationText; }
QString AppState::selectedFile() const { return m_selectedFile; }
void AppState::setCurrentUser(const QString &value) { if (m_currentUser == value) return; m_currentUser = value; emit currentUserChanged(); }
void AppState::setStatusMessage(const QString &value) { if (m_statusMessage == value) return; m_statusMessage = value; emit statusMessageChanged(); }
void AppState::setOperationText(const QString &value) { if (m_operationText == value) return; m_operationText = value; emit operationTextChanged(); }
void AppState::setSelectedFile(const QString &value) { if (m_selectedFile == value) return; m_selectedFile = value; emit selectedFileChanged(); }
