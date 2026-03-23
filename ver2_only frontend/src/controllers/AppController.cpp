#include "AppController.h"

AppController::AppController(QObject *parent) : QObject(parent)
{
    connect(&m_state, &AppState::currentUserChanged, this, &AppController::currentUserChanged);
    connect(&m_state, &AppState::statusMessageChanged, this, &AppController::statusMessageChanged);
    connect(&m_state, &AppState::operationTextChanged, this, &AppController::operationTextChanged);
    connect(&m_state, &AppState::selectedFileChanged, this, &AppController::selectedFileChanged);
}

QString AppController::currentUser() const { return m_state.currentUser(); }
QString AppController::statusMessage() const { return m_state.statusMessage(); }
QString AppController::operationText() const { return m_state.operationText(); }
QString AppController::selectedFile() const { return m_state.selectedFile(); }

void AppController::connectToHsm(const QString &userId)
{
    if (!m_authService.connectUser(userId)) {
        m_state.setStatusMessage("Please enter a user name.");
        return;
    }
    m_state.setCurrentUser(userId.trimmed());
    m_state.setStatusMessage("");
    QTimer::singleShot(1400, this, &AppController::finishConnect);
}

void AppController::goToRegeneratePage()
{
    emit openRegeneratePage();
}

void AppController::regeneratePublicKey(const QString &userId)
{
    if (!m_authService.regenerateKey(userId)) {
        m_state.setStatusMessage("Please enter a user name for key regeneration.");
        return;
    }
    m_state.setCurrentUser(userId.trimmed());
    m_state.setStatusMessage("Public key regenerated.");
    emit backToConnectPage();
}

void AppController::selectFile(const QString &path)
{
    m_state.setSelectedFile(path.trimmed());
    if (!path.trimmed().isEmpty())
        m_state.setStatusMessage("File selected.");
}

void AppController::uploadData()
{
    if (m_state.selectedFile().trimmed().isEmpty()) {
        m_state.setStatusMessage("Please select a file first.");
        return;
    }
    m_state.setStatusMessage("Upload complete.");
    emit openActionPage();
}

void AppController::startEncrypt()
{
    m_state.setOperationText("Encrypting...");
    QString msg;
    m_cryptoService.encrypt(m_state.selectedFile(), &msg);
    m_pendingResult = msg;
    emit openWorkLoadingPage();
    QTimer::singleShot(1400, this, &AppController::finishOperation);
}

void AppController::startDecrypt()
{
    m_state.setOperationText("Decrypting...");
    QString msg;
    m_cryptoService.decrypt(m_state.selectedFile(), &msg);
    m_pendingResult = msg;
    emit openWorkLoadingPage();
    QTimer::singleShot(1400, this, &AppController::finishOperation);
}

void AppController::finishConnect()
{
    emit connectSuccess();
}

void AppController::finishOperation()
{
    m_state.setStatusMessage(m_pendingResult.isEmpty() ? "Done." : m_pendingResult);
    emit operationFinished();
}
