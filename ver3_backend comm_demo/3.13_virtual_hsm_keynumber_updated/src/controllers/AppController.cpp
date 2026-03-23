#include "AppController.h"

#include <QFile>
#include <QRandomGenerator>
#include <QTimer>

#include "FileUtils.h"

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
    const QString trimmedUser = userId.trimmed();
    const QString trimmedHost = piHostOrName.trimmed();

    m_state.setStatusMessage(QString());

    if (!m_authService.validateUser(trimmedUser)) {
        m_state.setStatusMessage(QStringLiteral("유저명을 입력해주세요."));
        return false;
    }

    if (trimmedHost.isEmpty()) {
        m_state.setStatusMessage(QStringLiteral("Pi Tailscale IP 또는 MagicDNS를 입력해주세요."));
        return false;
    }

    m_state.setCurrentUser(trimmedUser);
    m_state.setCurrentPiHost(trimmedHost);
    m_state.setConnectionPhase(QStringLiteral("ML-DSA 인증 준비 중..."));
    m_state.setTerminalLog(QString());

    emit openConnectLoadingPage();
    QTimer::singleShot(0, this, &AppController::beginConnectionSequence);
    return true;
}

void AppController::goToRegeneratePage()
{
    m_state.setRegenerateStatusMessage(QString());
    emit openRegeneratePage();
}

void AppController::goBackToConnectPage()
{
    m_state.setRegenerateStatusMessage(QString());
    m_state.setLatestPublicKey(QString());
    emit backToConnectPage();
}

void AppController::regeneratePublicKey(const QString &userId, const QString &piHostOrName)
{
    const QString trimmedUser = userId.trimmed();
    const QString trimmedHost = piHostOrName.trimmed();

    if (!m_authService.validateUser(trimmedUser)) {
        m_state.setRegenerateStatusMessage(QStringLiteral("유저명을 입력해주세요."));
        return;
    }

    if (trimmedHost.isEmpty()) {
        m_state.setRegenerateStatusMessage(QStringLiteral("Pi Tailscale IP 또는 MagicDNS를 입력해주세요."));
        return;
    }

    const QString privateKeyPath = FileUtils::appPrivateKeyPathForUser(trimmedUser);
    const QString publicKeyPath = FileUtils::appPublicKeyPathForUser(trimmedUser);

    QString phonePublicKeyPem;
    QString errorMessage;
    if (!m_mldsaService.generateDeviceKeyPair(privateKeyPath, publicKeyPath, &phonePublicKeyPem, &errorMessage)) {
        m_state.setRegenerateStatusMessage(errorMessage.isEmpty()
                                               ? QStringLiteral("스마트폰 공개키 재발급에 실패했습니다.")
                                               : errorMessage);
        return;
    }

    QString piPublicKeyPem;
    if (!m_piGatewayService.provisionDevice(trimmedUser,
                                            trimmedHost,
                                            phonePublicKeyPem,
                                            &piPublicKeyPem,
                                            &errorMessage)) {
        m_state.setRegenerateStatusMessage(errorMessage.isEmpty()
                                               ? QStringLiteral("Pi 공개키 등록에 실패했습니다.")
                                               : errorMessage);
        return;
    }

    const QString trustedPiPath = FileUtils::trustedPiPublicKeyPathForUser(trimmedUser);
    if (!FileUtils::writeTextFile(trustedPiPath, piPublicKeyPem, &errorMessage)) {
        m_state.setRegenerateStatusMessage(errorMessage.isEmpty()
                                               ? QStringLiteral("Pi 공개키 저장에 실패했습니다.")
                                               : errorMessage);
        return;
    }

    m_state.setLatestPublicKey(publicKeyPath);
    m_state.setRegenerateStatusMessage(QStringLiteral("공개키 재발급 및 Pi 등록이 완료되었습니다."));
}

void AppController::selectFile(const QString &path)
{
    m_state.setSelectedFile(path);
}

void AppController::uploadData()
{
    if (m_state.selectedFile().trimmed().isEmpty()) {
        m_state.setStatusMessage(QStringLiteral("파일 경로를 입력해주세요."));
        return;
    }

    m_state.setStatusMessage(QStringLiteral("파일 업로드가 완료되었습니다."));
    emit openActionPage();
}

void AppController::startEncrypt()
{
    QString message;
    if (!m_cryptoService.encrypt(m_state.selectedFile(), &message)) {
        m_state.setStatusMessage(message);
        return;
    }

    m_state.setStatusMessage(message);
}

void AppController::startDecrypt()
{
    QString message;
    if (!m_cryptoService.decrypt(m_state.selectedFile(), &message)) {
        m_state.setStatusMessage(message);
        return;
    }

    m_state.setStatusMessage(message);
}

void AppController::startEncryptWithKey(const QString &keyNumber)
{
    const QString trimmed = keyNumber.trimmed();
    if (trimmed != QStringLiteral("1") && trimmed != QStringLiteral("2") && trimmed != QStringLiteral("3")) {
        m_state.setStatusMessage(QStringLiteral("키 번호는 1, 2, 3 중 하나만 입력 가능합니다."));
        return;
    }

    QString errorMessage;
    if (!m_piGatewayService.sendKeyCommand(m_state.currentUser(),
                                           m_state.currentPiHost(),
                                           QStringLiteral("encrypt"),
                                           trimmed,
                                           &errorMessage)) {
        m_state.setStatusMessage(errorMessage.isEmpty()
                                     ? QStringLiteral("암호화 명령 전송에 실패했습니다.")
                                     : errorMessage);
        return;
    }

    const QString pinLabel = trimmed == QStringLiteral("1") ? QStringLiteral("D3")
                             : trimmed == QStringLiteral("2") ? QStringLiteral("D4")
                                                               : QStringLiteral("D5");
    m_state.setStatusMessage(QStringLiteral("암호화 명령을 전송했습니다. 키 %1 → Arduino %2 ON").arg(trimmed, pinLabel));
}

void AppController::startDecryptWithKey(const QString &keyNumber)
{
    const QString trimmed = keyNumber.trimmed();
    if (trimmed != QStringLiteral("1") && trimmed != QStringLiteral("2") && trimmed != QStringLiteral("3")) {
        m_state.setStatusMessage(QStringLiteral("키 번호는 1, 2, 3 중 하나만 입력 가능합니다."));
        return;
    }

    QString errorMessage;
    if (!m_piGatewayService.sendKeyCommand(m_state.currentUser(),
                                           m_state.currentPiHost(),
                                           QStringLiteral("decrypt"),
                                           trimmed,
                                           &errorMessage)) {
        m_state.setStatusMessage(errorMessage.isEmpty()
                                     ? QStringLiteral("복호화 명령 전송에 실패했습니다.")
                                     : errorMessage);
        return;
    }

    const QString pinLabel = trimmed == QStringLiteral("1") ? QStringLiteral("D3")
                             : trimmed == QStringLiteral("2") ? QStringLiteral("D4")
                                                               : QStringLiteral("D5");
    m_state.setStatusMessage(QStringLiteral("복호화 명령을 전송했습니다. 키 %1 → Arduino %2 ON").arg(trimmed, pinLabel));
}

void AppController::appendTerminalLine(const QString &line)
{
    const QString current = m_state.terminalLog();
    m_state.setTerminalLog(current.isEmpty() ? line : current + QStringLiteral("\n") + line);
}

void AppController::updateConnectionPhase(const QString &phase)
{
    m_state.setConnectionPhase(phase);
}

bool AppController::ensureDeviceKeyPair(const QString &userId,
                                        QString *publicKeyPem,
                                        QString *privateKeyPem,
                                        QString *errorMessage) const
{
    const QString publicKeyPath = FileUtils::appPublicKeyPathForUser(userId);
    const QString privateKeyPath = FileUtils::appPrivateKeyPathForUser(userId);

    if (!QFile::exists(publicKeyPath) || !QFile::exists(privateKeyPath)) {
        return m_mldsaService.generateDeviceKeyPair(privateKeyPath,
                                                    publicKeyPath,
                                                    publicKeyPem,
                                                    errorMessage);
    }

    QString fileError;
    const QString loadedPublic = FileUtils::readTextFile(publicKeyPath, &fileError);
    if (loadedPublic.isEmpty()) {
        if (errorMessage)
            *errorMessage = fileError;
        return false;
    }

    const QString loadedPrivate = FileUtils::readTextFile(privateKeyPath, &fileError);
    if (loadedPrivate.isEmpty()) {
        if (errorMessage)
            *errorMessage = fileError;
        return false;
    }

    if (publicKeyPem)
        *publicKeyPem = loadedPublic;
    if (privateKeyPem)
        *privateKeyPem = loadedPrivate;
    if (errorMessage)
        errorMessage->clear();
    return true;
}

QByteArray AppController::generateRandomChallenge(int size) const
{
    QByteArray challenge(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i)
        challenge[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));
    return challenge;
}

void AppController::beginConnectionSequence()
{
    const QString userId = m_state.currentUser();
    const QString piHost = m_state.currentPiHost();

    QString phonePublicKeyPem;
    QString phonePrivateKeyPem;
    QString errorMessage;

    updateConnectionPhase(QStringLiteral("스마트폰 키 확인 중..."));
    appendTerminalLine(QStringLiteral("[APP] 스마트폰 ML-DSA 키 확인 시작"));
    if (!ensureDeviceKeyPair(userId, &phonePublicKeyPem, &phonePrivateKeyPem, &errorMessage)) {
        m_state.setStatusMessage(errorMessage);
        emit backToConnectPage();
        return;
    }

    updateConnectionPhase(QStringLiteral("Pi 공개키 등록 확인 중..."));
    QString piPublicKeyPem;
    appendTerminalLine(QStringLiteral("[APP] Pi 공개키 등록 요청"));
    if (!m_piGatewayService.provisionDevice(userId, piHost, phonePublicKeyPem, &piPublicKeyPem, &errorMessage)) {
        m_state.setStatusMessage(errorMessage);
        emit backToConnectPage();
        return;
    }

    const QString trustedPiPath = FileUtils::trustedPiPublicKeyPathForUser(userId);
    if (!FileUtils::writeTextFile(trustedPiPath, piPublicKeyPem, &errorMessage)) {
        m_state.setStatusMessage(errorMessage);
        emit backToConnectPage();
        return;
    }

    updateConnectionPhase(QStringLiteral("Pi 서명 검증 중..."));
    appendTerminalLine(QStringLiteral("[APP] Challenge 교환 시작"));
    const QByteArray clientChallenge = generateRandomChallenge(32);
    QString sessionId;
    QByteArray serverChallenge;
    QByteArray piSignature;

    if (!m_piGatewayService.startMutualAuthentication(userId,
                                                      piHost,
                                                      clientChallenge,
                                                      &sessionId,
                                                      &piPublicKeyPem,
                                                      &serverChallenge,
                                                      &piSignature,
                                                      &errorMessage)) {
        m_state.setStatusMessage(errorMessage);
        emit backToConnectPage();
        return;
    }

    if (!m_mldsaService.verifyMessage(piPublicKeyPem, clientChallenge, piSignature, &errorMessage)) {
        m_state.setStatusMessage(errorMessage.isEmpty()
                                     ? QStringLiteral("Pi 서명 검증에 실패했습니다.")
                                     : errorMessage);
        emit backToConnectPage();
        return;
    }

    updateConnectionPhase(QStringLiteral("스마트폰 서명 생성 중..."));
    QByteArray phoneSignature;
    if (!m_mldsaService.signMessage(phonePrivateKeyPem, serverChallenge, &phoneSignature, &errorMessage)) {
        m_state.setStatusMessage(errorMessage);
        emit backToConnectPage();
        return;
    }

    updateConnectionPhase(QStringLiteral("상호인증 완료 중..."));
    if (!m_piGatewayService.finishMutualAuthentication(userId,
                                                       piHost,
                                                       sessionId,
                                                       phoneSignature,
                                                       &errorMessage)) {
        m_state.setStatusMessage(errorMessage);
        emit backToConnectPage();
        return;
    }

    appendTerminalLine(QStringLiteral("[APP] 상호인증 성공"));
    finishConnect();
}

void AppController::finishConnect()
{
    m_state.setStatusMessage(QString());
    m_state.setConnectionPhase(QStringLiteral("인증 완료"));
    emit connectSuccess();
}

void AppController::finishRegenerate() {}
void AppController::finishOperation() {}
