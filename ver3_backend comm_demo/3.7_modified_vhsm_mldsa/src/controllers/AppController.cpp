#include "AppController.h"

#include <QtConcurrent/QtConcurrent>
#include <QVariantMap>

AppController::AppController(QObject *parent) : QObject(parent)
{
    connect(&m_state, &AppState::currentUserChanged, this, &AppController::currentUserChanged);
    connect(&m_state, &AppState::statusMessageChanged, this, &AppController::statusMessageChanged);
    connect(&m_state, &AppState::regenerateStatusMessageChanged, this, &AppController::regenerateStatusMessageChanged);
    connect(&m_state, &AppState::operationTextChanged, this, &AppController::operationTextChanged);
    connect(&m_state, &AppState::selectedFileChanged, this, &AppController::selectedFileChanged);
    connect(&m_state, &AppState::connectionPhaseChanged, this, &AppController::connectionPhaseChanged);
    connect(&m_state, &AppState::terminalLogChanged, this, &AppController::terminalLogChanged);
    connect(&m_state, &AppState::latestPublicKeyChanged, this, &AppController::latestPublicKeyChanged);

    connect(&m_authWatcher, &QFutureWatcher<QVariantMap>::finished, this, [this]() {
        const QVariantMap result = m_authWatcher.result();
        const bool ok = result.value(QStringLiteral("ok")).toBool();
        const QString error = result.value(QStringLiteral("error")).toString();

        if (!ok) {
            m_state.setConnectionPhase(QStringLiteral("ML-DSA 인증 실패"));
            m_state.setStatusMessage(error.isEmpty() ? QStringLiteral("ML-DSA 인증에 실패했습니다.") : error);
            emit backToConnectPage();
            return;
        }

        m_state.setConnectionPhase(QStringLiteral("ML-DSA 인증 완료"));
        QTimer::singleShot(250, this, &AppController::finishConnect);
    });

    connect(&m_regenerateWatcher, &QFutureWatcher<QVariantMap>::finished, this, [this]() {
        const QVariantMap result = m_regenerateWatcher.result();
        const bool ok = result.value(QStringLiteral("ok")).toBool();
        const QString error = result.value(QStringLiteral("error")).toString();
        const QString publicKey = result.value(QStringLiteral("publicKey")).toString();

        if (!ok) {
            m_state.setRegenerateStatusMessage(error.isEmpty()
                                                  ? QStringLiteral("공개키 재생성에 실패했습니다.")
                                                  : error);
            return;
        }

        m_state.setLatestPublicKey(publicKey);
        finishRegenerate();
    });
}

QString AppController::currentUser() const { return m_state.currentUser(); }
QString AppController::statusMessage() const { return m_state.statusMessage(); }
QString AppController::regenerateStatusMessage() const { return m_state.regenerateStatusMessage(); }
QString AppController::operationText() const { return m_state.operationText(); }
QString AppController::selectedFile() const { return m_state.selectedFile(); }
QString AppController::connectionPhase() const { return m_state.connectionPhase(); }
QString AppController::terminalLog() const { return m_state.terminalLog(); }
QString AppController::latestPublicKey() const { return m_state.latestPublicKey(); }

bool AppController::connectToHsm(const QString &userId, const QString &piHostOrName)
{
    if (m_authWatcher.isRunning())
        return false;

    const QString trimmedUser = userId.trimmed();
    const QString trimmedHost = piHostOrName.trimmed();

    if (!m_authService.connectUser(trimmedUser)) {
        m_state.setStatusMessage(QStringLiteral("유저명을 입력해주세요."));
        return false;
    }

    if (trimmedHost.isEmpty()) {
        m_state.setStatusMessage(QStringLiteral("Tailscale IP 주소를 입력해주세요."));
        return false;
    }

    m_state.setCurrentUser(trimmedUser);
    m_state.setStatusMessage(QString());
    m_state.setConnectionPhase(QStringLiteral("ML-DSA 인증 준비 중"));
    m_state.setTerminalLog(QString());
    emit openConnectLoadingPage();

    m_authWatcher.setFuture(QtConcurrent::run([this, trimmedUser, trimmedHost]() {
        QVariantMap result;
        QString errorMessage;
        const bool ok = m_piGatewayService.authenticateUser(trimmedUser, trimmedHost, &errorMessage);
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("error"), errorMessage);
        return result;
    }));

    return true;
}

void AppController::goToRegeneratePage()
{
    m_state.setStatusMessage(QString());
    m_state.setRegenerateStatusMessage(QString());
    emit openRegeneratePage();
}

void AppController::goBackToConnectPage()
{
    m_state.setRegenerateStatusMessage(QString());
    m_state.setStatusMessage(QString());
    emit backToConnectPage();
}

void AppController::regeneratePublicKey(const QString &userId, const QString &piHostOrName)
{
    if (m_regenerateWatcher.isRunning())
        return;

    const QString trimmedUser = userId.trimmed();
    if (!m_authService.regenerateKey(trimmedUser)) {
        m_state.setRegenerateStatusMessage(QStringLiteral("재발급할 유저명을 입력해주세요."));
        return;
    }

    m_state.setCurrentUser(trimmedUser);
    m_state.setRegenerateStatusMessage(QStringLiteral("ML-DSA 공개키/비밀키 생성 중..."));
    m_state.setStatusMessage(QString());
    m_state.setLatestPublicKey(QString());

    const QString trimmedHost = piHostOrName.trimmed();
    if (trimmedHost.isEmpty()) {
        m_state.setRegenerateStatusMessage(QStringLiteral("Tailscale IP 주소를 입력해주세요."));
        return;
    }

    m_regenerateWatcher.setFuture(QtConcurrent::run([this, trimmedUser, trimmedHost]() {
        QVariantMap result;
        QString errorMessage;
        QString publicKeyPem;
        const bool ok = m_piGatewayService.regeneratePublicKey(trimmedUser,
                                                               trimmedHost,
                                                               &publicKeyPem,
                                                               &errorMessage);
        result.insert(QStringLiteral("ok"), ok);
        result.insert(QStringLiteral("error"), errorMessage);
        result.insert(QStringLiteral("publicKey"), publicKeyPem);
        return result;
    }));
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
    updateConnectionPhase(QStringLiteral("ML-DSA 인증 중"));
}

void AppController::finishConnect()
{
    emit connectSuccess();
}

void AppController::finishRegenerate()
{
    m_state.setRegenerateStatusMessage(QStringLiteral("공개키 재생성 완료"));
}

void AppController::finishOperation()
{
    m_state.setStatusMessage(m_pendingResult.isEmpty() ? "Done." : m_pendingResult);
    emit operationFinished();
}
