#include "AppState.h"

AppState::AppState(QObject *parent)
    : QObject(parent), m_operationText(QStringLiteral("Working..."))
{}

// ── 공통 setter/getter 구현 매크로 ─────────────────────────────────────────

#define DEF_PROP(T, name, signal) \
    T AppState::name() const { return m_##name; } \
    void AppState::set##name(const T &v) { \
        if (m_##name == v) return; \
        m_##name = v; \
        emit signal(); \
    }

// 첫 글자를 대문자로 맞춰야 해서 수동 구현
QString AppState::currentUser() const { return m_currentUser; }
void AppState::setCurrentUser(const QString &v)               { if (m_currentUser==v) return; m_currentUser=v; emit currentUserChanged(); }

QString AppState::currentPiHost() const { return m_currentPiHost; }
void AppState::setCurrentPiHost(const QString &v)             { if (m_currentPiHost==v) return; m_currentPiHost=v; emit currentPiHostChanged(); }

QString AppState::statusMessage() const { return m_statusMessage; }
void AppState::setStatusMessage(const QString &v)             { if (m_statusMessage==v) return; m_statusMessage=v; emit statusMessageChanged(); }

QString AppState::regenerateStatusMessage() const { return m_regenerateStatusMessage; }
void AppState::setRegenerateStatusMessage(const QString &v)   { if (m_regenerateStatusMessage==v) return; m_regenerateStatusMessage=v; emit regenerateStatusMessageChanged(); }

QString AppState::operationText() const { return m_operationText; }
void AppState::setOperationText(const QString &v)             { if (m_operationText==v) return; m_operationText=v; emit operationTextChanged(); }

QString AppState::selectedFile() const { return m_selectedFile; }
void AppState::setSelectedFile(const QString &v)              { if (m_selectedFile==v) return; m_selectedFile=v; emit selectedFileChanged(); }

QString AppState::connectionPhase() const { return m_connectionPhase; }
void AppState::setConnectionPhase(const QString &v)           { if (m_connectionPhase==v) return; m_connectionPhase=v; emit connectionPhaseChanged(); }

QString AppState::terminalLog() const { return m_terminalLog; }
void AppState::setTerminalLog(const QString &v)               { if (m_terminalLog==v) return; m_terminalLog=v; emit terminalLogChanged(); }

QString AppState::latestPublicKey() const { return m_latestPublicKey; }
void AppState::setLatestPublicKey(const QString &v)           { if (m_latestPublicKey==v) return; m_latestPublicKey=v; emit latestPublicKeyChanged(); }

QString AppState::signUpStatusMessage() const { return m_signUpStatusMessage; }
void AppState::setSignUpStatusMessage(const QString &v)       { if (m_signUpStatusMessage==v) return; m_signUpStatusMessage=v; emit signUpStatusMessageChanged(); }

QString AppState::findIdStatusMessage() const { return m_findIdStatusMessage; }
void AppState::setFindIdStatusMessage(const QString &v)       { if (m_findIdStatusMessage==v) return; m_findIdStatusMessage=v; emit findIdStatusMessageChanged(); }

QString AppState::findPasswordStatusMessage() const { return m_findPasswordStatusMessage; }
void AppState::setFindPasswordStatusMessage(const QString &v) { if (m_findPasswordStatusMessage==v) return; m_findPasswordStatusMessage=v; emit findPasswordStatusMessageChanged(); }

QString AppState::resetPasswordStatusMessage() const { return m_resetPasswordStatusMessage; }
void AppState::setResetPasswordStatusMessage(const QString &v){ if (m_resetPasswordStatusMessage==v) return; m_resetPasswordStatusMessage=v; emit resetPasswordStatusMessageChanged(); }

QString AppState::pendingResetUserId() const { return m_pendingResetUserId; }
void AppState::setPendingResetUserId(const QString &v)        { if (m_pendingResetUserId==v) return; m_pendingResetUserId=v; emit pendingResetUserIdChanged(); }

QString AppState::tlsSessionStatus() const { return m_tlsSessionStatus; }
void AppState::setTlsSessionStatus(const QString &v)          { if (m_tlsSessionStatus==v) return; m_tlsSessionStatus=v; emit tlsSessionStatusChanged(); }

QString AppState::tlsSignaturePreview() const { return m_tlsSignaturePreview; }
void AppState::setTlsSignaturePreview(const QString &v) {
    if (m_tlsSignaturePreview == v) return;
    m_tlsSignaturePreview = v;
    emit tlsSignaturePreviewChanged();
}
