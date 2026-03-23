#include "AppController.h"

#include <QtConcurrent/QtConcurrent>
#include <QRandomGenerator>
#include <QTimer>
#include <QVariantMap>

#include "FileUtils.h"

namespace {
QByteArray randomBytes(int size)
{
    QByteArray out(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i)
        out[i] = static_cast<char>(QRandomGenerator::global()->generate() & 0xFF);
    return out;
}

QByteArray buildPiAuthPayload(const QString &userId,
                              const QString &sessionId,
                              const QByteArray &clientChallenge,
                              const QByteArray &serverChallenge)
{
    return QStringLiteral("PI_AUTH|%1|%2|%3|%4")
        .arg(userId,
             sessionId,
             QString::fromLatin1(clientChallenge.toBase64()),
             QString::fromLatin1(serverChallenge.toBase64()))
        .toUtf8();
}

QByteArray buildPhoneAuthPayload(const QString &userId,
                                 const QString &sessionId,
                                 const QByteArray &clientChallenge,
                                 const QByteArray &serverChallenge)
{
    return QStringLiteral("PHONE_AUTH|%1|%2|%3|%4")
        .arg(userId,
             sessionId,
             QString::fromLatin1(clientChallenge.toBase64()),
             QString::fromLatin1(serverChallenge.toBase64()))
        .toUtf8();
}
}

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
            m_state.setConnectionPhase(QStringLiteral("상호인증 실패"));
            m_state.setStatusMessage(error.isEmpty() ? QStringLiteral("상호인증에 실패했습니다.") : error);
            emit backToConnectPage();
            return;
        }

        m_state.setConnectionPhase(QStringLiteral("상호인증 완료"));
        QTimer::singleShot(250, this, &AppController::finishConnect);
    });

    connect(&m_regenerateWatcher, &QFutureWatcher<QVariantMap>::finished, this, [this]() {
        const QVariantMap result = m_regenerateWatcher.result();
        const bool ok = result.value(QStringLiteral("ok")).toBool();
        const QString error = result.value(QStringLiteral("error")).toString();
        const QString publicKeyPath = result.value(QStringLiteral("publicKeyPath")).toString();

        if (!ok) {
            m_state.setRegenerateStatusMessage(error.isEmpty()
                                               ? QStringLiteral("키 준비에 실패했습니다.")
                                               : error);
            return;
        }

        m_state.setLatestPublicKey(publicKeyPath);
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

    QString fileError;
    const QString phonePrivateKeyPath = FileUtils::appPrivateKeyPathForUser(trimmedUser);
    const QString trustedPiPublicKeyPath = FileUtils::trustedPiPublicKeyPathForUser(trimmedUser);
    const QString phonePrivateKeyPem = FileUtils::readTextFile(phonePrivateKeyPath, &fileError);
    if (phonePrivateKeyPem.trimmed().isEmpty()) {
        m_state.setStatusMessage(fileError.isEmpty()
                                 ? QStringLiteral("스마트폰 개인키 파일이 없습니다. 먼저 키 준비를 진행해주세요.")
                                 : fileError);
        return false;
    }

    const QString trustedPiPublicKeyPem = FileUtils::readTextFile(trustedPiPublicKeyPath, &fileError);
    if (trustedPiPublicKeyPem.trimmed().isEmpty()) {
        m_state.setStatusMessage(fileError.isEmpty()
                                 ? QStringLiteral("신뢰된 Pi 공개키 파일이 없습니다. 먼저 키 준비를 진행해주세요.")
                                 : fileError);
        return false;
    }

    m_state.setCurrentUser(trimmedUser);
    m_state.setStatusMessage(QString());
    m_state.setConnectionPhase(QStringLiteral("Pi와 상호인증 준비 중"));
    m_state.setTerminalLog(QString());
    emit openConnectLoadingPage();

    m_authWatcher.setFuture(QtConcurrent::run([this, trimmedUser, trimmedHost, phonePrivateKeyPem, trustedPiPublicKeyPem]() {
        QVariantMap result;
        QString errorMessage;

        const QByteArray clientChallenge = randomBytes(32);
        if (clientChallenge.isEmpty()) {
            result.insert(QStringLiteral("ok"), false);
            result.insert(QStringLiteral("error"), QStringLiteral("클라이언트 challenge 생성에 실패했습니다."));
            return result;
        }

        QString sessionId;
        QString piPublicKeyPem;
        QByteArray serverChallenge;
        QByteArray piSignature;
        if (!m_piGatewayService.startMutualAuthentication(trimmedUser,
                                                          trimmedHost,
                                                          clientChallenge,
                                                          &sessionId,
                                                          &piPublicKeyPem,
                                                          &serverChallenge,
                                                          &piSignature,
                                                          &errorMessage)) {
            result.insert(QStringLiteral("ok"), false);
            result.insert(QStringLiteral("error"), errorMessage);
            return result;
        }

        const QString normalizedTrustedPi = trustedPiPublicKeyPem.trimmed();
        const QString normalizedReceivedPi = piPublicKeyPem.trimmed();
        if (normalizedTrustedPi != normalizedReceivedPi) {
            result.insert(QStringLiteral("ok"), false);
            result.insert(QStringLiteral("error"), QStringLiteral("Pi 공개키가 기존에 신뢰한 공개키와 일치하지 않습니다."));
            return result;
        }

        const QByteArray piPayload = buildPiAuthPayload(trimmedUser, sessionId, clientChallenge, serverChallenge);
        if (!m_mldsaService.verifyMessage(piPublicKeyPem, piPayload, piSignature, &errorMessage)) {
            result.insert(QStringLiteral("ok"), false);
            result.insert(QStringLiteral("error"), errorMessage.isEmpty()
                                                  ? QStringLiteral("Pi 서명 검증에 실패했습니다.")
                                                  : errorMessage);
            return result;
        }

        QByteArray phoneSignature;
        const QByteArray phonePayload = buildPhoneAuthPayload(trimmedUser, sessionId, clientChallenge, serverChallenge);
        if (!m_mldsaService.signMessage(phonePrivateKeyPem, phonePayload, &phoneSignature, &errorMessage)) {
            result.insert(QStringLiteral("ok"), false);
            result.insert(QStringLiteral("error"), errorMessage.isEmpty()
                                                  ? QStringLiteral("스마트폰 서명 생성에 실패했습니다.")
                                                  : errorMessage);
            return result;
        }

        const bool ok = m_piGatewayService.finishMutualAuthentication(trimmedUser,
                                                                      trimmedHost,
                                                                      sessionId,
                                                                      phoneSignature,
                                                                      &errorMessage);
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
    m_state.setRegenerateStatusMessage(QStringLiteral("스마트폰/Pi ML-DSA 키를 준비 중입니다..."));
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
        QString phonePublicKeyPem;

        const QString privateKeyPath = FileUtils::appPrivateKeyPathForUser(trimmedUser);
        const QString publicKeyPath = FileUtils::appPublicKeyPathForUser(trimmedUser);
        if (!m_mldsaService.generateDeviceKeyPair(privateKeyPath,
                                                  publicKeyPath,
                                                  &phonePublicKeyPem,
                                                  &errorMessage)) {
            result.insert(QStringLiteral("ok"), false);
            result.insert(QStringLiteral("error"), errorMessage);
            return result;
        }

        QString piPublicKeyPem;
        if (!m_piGatewayService.provisionDevice(trimmedUser,
                                                trimmedHost,
                                                phonePublicKeyPem,
                                                &piPublicKeyPem,
                                                &errorMessage)) {
            result.insert(QStringLiteral("ok"), false);
            result.insert(QStringLiteral("error"), errorMessage);
            return result;
        }

        const QString trustedPiPath = FileUtils::trustedPiPublicKeyPathForUser(trimmedUser);
        QString fileError;
        if (!FileUtils::writeTextFile(trustedPiPath, piPublicKeyPem, &fileError)) {
            result.insert(QStringLiteral("ok"), false);
            result.insert(QStringLiteral("error"), fileError);
            return result;
        }

        result.insert(QStringLiteral("ok"), true);
        result.insert(QStringLiteral("publicKeyPath"), publicKeyPath);
        return result;
    }));
}

void AppController::selectFile(const QString &path)
{
    m_state.setSelectedFile(path.trimmed());
    if (!path.trimmed().isEmpty())
        m_state.setStatusMessage(QStringLiteral("File selected."));
}

void AppController::uploadData()
{
    if (m_state.selectedFile().trimmed().isEmpty()) {
        m_state.setStatusMessage(QStringLiteral("Please select a file first."));
        return;
    }
    m_state.setStatusMessage(QStringLiteral("Upload complete."));
    emit openActionPage();
}

void AppController::startEncrypt()
{
    m_state.setOperationText(QStringLiteral("Encrypting..."));
    QString msg;
    m_cryptoService.encrypt(m_state.selectedFile(), &msg);
    m_pendingResult = msg;
    emit openWorkLoadingPage();
    QTimer::singleShot(1400, this, &AppController::finishOperation);
}

void AppController::startDecrypt()
{
    m_state.setOperationText(QStringLiteral("Decrypting..."));
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
    updateConnectionPhase(QStringLiteral("상호인증 중"));
}

void AppController::finishConnect()
{
    emit connectSuccess();
}

void AppController::finishRegenerate()
{
    m_state.setRegenerateStatusMessage(QStringLiteral("스마트폰 키쌍과 신뢰된 Pi 공개키를 저장했습니다."));
}

void AppController::finishOperation()
{
    m_state.setStatusMessage(m_pendingResult.isEmpty() ? QStringLiteral("Done.") : m_pendingResult);
    emit operationFinished();
}
