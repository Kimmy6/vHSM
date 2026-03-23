#include "AppController.h"

AppController::AppController(QObject *parent) : QObject(parent)
{
    connect(&m_state, &AppState::currentUserChanged, this, &AppController::currentUserChanged);
    connect(&m_state, &AppState::statusMessageChanged, this, &AppController::statusMessageChanged);
    connect(&m_state, &AppState::operationTextChanged, this, &AppController::operationTextChanged);
    connect(&m_state, &AppState::selectedFileChanged, this, &AppController::selectedFileChanged);
    connect(&m_state, &AppState::connectionPhaseChanged, this, &AppController::connectionPhaseChanged);
    connect(&m_state, &AppState::terminalLogChanged, this, &AppController::terminalLogChanged);
}

QString AppController::currentUser() const { return m_state.currentUser(); }
QString AppController::statusMessage() const { return m_state.statusMessage(); }
QString AppController::operationText() const { return m_state.operationText(); }
QString AppController::selectedFile() const { return m_state.selectedFile(); }
QString AppController::connectionPhase() const { return m_state.connectionPhase(); }
QString AppController::terminalLog() const { return m_state.terminalLog(); }

bool AppController::connectToHsm(const QString &userId)
{
    if (!m_authService.connectUser(userId)) {
        m_state.setStatusMessage("Please enter a user name.");
        return false;
    }

    QString errorMessage;
    if (!m_piGatewayService.requestUserConnectStart(userId, &errorMessage)) {
        m_state.setStatusMessage(errorMessage.isEmpty() ? QStringLiteral("Failed to notify Raspberry Pi.") : errorMessage);
        return false;
    }

    const QString trimmedUser = userId.trimmed();
    m_state.setCurrentUser(trimmedUser);
    m_state.setStatusMessage("");
    m_state.setConnectionPhase(QStringLiteral("라즈베리파이에 접속 요청을 전송했습니다."));
    m_state.setTerminalLog(QStringLiteral("Pi LXTerminal에서 진행 로그를 확인하세요."));

    beginConnectionSequence();
    return true;
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

void AppController::appendTerminalLine(const QString &line)
{
    QString current = m_state.terminalLog();
    if (!current.isEmpty())
        current += '\n';
    current += line;
    m_state.setTerminalLog(current);
}

void AppController::updateConnectionPhase(const QString &phase)
{
    m_state.setConnectionPhase(phase);
}

void AppController::beginConnectionSequence()
{
    appendTerminalLine(QStringLiteral("START_USER_CONNECT 명령이 Pi로 전송되었습니다."));
    updateConnectionPhase(QStringLiteral("Raspberry Pi가 LXTerminal을 여는 중..."));

    QTimer::singleShot(1000, this, [this]() {
        appendTerminalLine(QStringLiteral("Pi LXTerminal에서 아래 진행 로그가 표시됩니다:"));
        appendTerminalLine(QStringLiteral("- User 접속 시작"));
        appendTerminalLine(QStringLiteral("- RSA 인증 중..."));
        appendTerminalLine(QStringLiteral("- RSA 인증 완료!"));
        appendTerminalLine(QStringLiteral("- User 접속 중"));
        updateConnectionPhase(QStringLiteral("Pi에서 인증 절차가 진행 중입니다."));
    });

    QTimer::singleShot(2600, this, [this]() {
        updateConnectionPhase(QStringLiteral("가상 HSM 접속 완료"));
        finishConnect();
    });
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
