#include "AppController.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRandomGenerator>
#include <QStandardPaths>
#include <QTimer>
#include <QtConcurrent/QtConcurrent>

#include "FileUtils.h"

namespace {
// 단방향 인증 페이로드 — tcp_server.py build_pi_auth_payload() 와 반드시 일치
QByteArray buildPiAuthPayload(const QString &userId, const QByteArray &nonce)
{
    return QStringLiteral("PI_AUTH|%1|%2")
        .arg(userId, QString::fromLatin1(nonce.toBase64()))
        .toUtf8();
}
} // namespace


AppController::AppController(QObject *parent) : QObject(parent)
{
    connect(&m_state, &AppState::currentUserChanged,              this, &AppController::currentUserChanged);
    connect(&m_state, &AppState::statusMessageChanged,            this, &AppController::statusMessageChanged);
    connect(&m_state, &AppState::regenerateStatusMessageChanged,  this, &AppController::regenerateStatusMessageChanged);
    connect(&m_state, &AppState::operationTextChanged,            this, &AppController::operationTextChanged);
    connect(&m_state, &AppState::selectedFileChanged,             this, &AppController::selectedFileChanged);
    connect(&m_state, &AppState::connectionPhaseChanged,          this, &AppController::connectionPhaseChanged);
    connect(&m_state, &AppState::terminalLogChanged,              this, &AppController::terminalLogChanged);
    connect(&m_state, &AppState::latestPublicKeyChanged,          this, &AppController::latestPublicKeyChanged);
    connect(&m_state, &AppState::signUpStatusMessageChanged,       this, &AppController::signUpStatusMessageChanged);
    connect(&m_state, &AppState::findIdStatusMessageChanged,       this, &AppController::findIdStatusMessageChanged);
    connect(&m_state, &AppState::findPasswordStatusMessageChanged, this, &AppController::findPasswordStatusMessageChanged);
    connect(&m_state, &AppState::resetPasswordStatusMessageChanged,this, &AppController::resetPasswordStatusMessageChanged);
    connect(&m_state, &AppState::tlsSessionStatusChanged,          this, &AppController::tlsSessionStatusChanged);
    connect(&m_state, &AppState::tlsSignaturePreviewChanged,       this, &AppController::tlsSignaturePreviewChanged);
    connect(&m_state, &AppState::cryptoResultChanged,              this, &AppController::cryptoResultChanged);
    connect(&m_state, &AppState::resultFilePathChanged,            this, &AppController::resultFilePathChanged);
    connect(&m_state, &AppState::currentRoleChanged,            this, &AppController::currentRoleChanged);
    connect(&m_state, &AppState::auditLogJsonChanged,           this, &AppController::auditLogJsonChanged);
}

// ── 프로퍼티 읽기 ───────────────────────────────────────────────────────────


// ── 소멸자: 앱 종료 시 persistent 세션 정상 종료 ─────────────────────────────
AppController::~AppController()
{
    m_piGatewayService.closeSession();
}

QString AppController::currentUser()              const { return m_state.currentUser(); }
QString AppController::statusMessage()            const { return m_state.statusMessage(); }
QString AppController::regenerateStatusMessage()  const { return m_state.regenerateStatusMessage(); }
QString AppController::operationText()            const { return m_state.operationText(); }
QString AppController::selectedFile()             const { return m_state.selectedFile(); }
QString AppController::connectionPhase()          const { return m_state.connectionPhase(); }
QString AppController::terminalLog()              const { return m_state.terminalLog(); }
QString AppController::latestPublicKey()          const { return m_state.latestPublicKey(); }
QString AppController::signUpStatusMessage()       const { return m_state.signUpStatusMessage(); }
QString AppController::findIdStatusMessage()       const { return m_state.findIdStatusMessage(); }
QString AppController::findPasswordStatusMessage() const { return m_state.findPasswordStatusMessage(); }
QString AppController::resetPasswordStatusMessage()const { return m_state.resetPasswordStatusMessage(); }
QString AppController::currentRole()               const { return m_state.currentRole(); }
QString AppController::auditLogJson()              const { return m_state.auditLogJson(); }
QString AppController::tlsSessionStatus()          const { return m_state.tlsSessionStatus(); }
QString AppController::tlsSignaturePreview()        const { return m_state.tlsSignaturePreview(); }
QString AppController::cryptoResult()               const { return m_state.cryptoResult(); }
QString AppController::resultFilePath()             const { return m_state.resultFilePath(); }


// ── 내부 헬퍼 ───────────────────────────────────────────────────────────────

void AppController::appendTerminalLine(const QString &line)
{
    const QString cur = m_state.terminalLog();
    m_state.setTerminalLog(cur.isEmpty() ? line : cur + QStringLiteral("\n") + line);
}

void AppController::updateConnectionPhase(const QString &phase)
{
    m_state.setConnectionPhase(phase);
}

QByteArray AppController::generateRandomNonce(int size) const
{
    QByteArray nonce(size, Qt::Uninitialized);
    for (int i = 0; i < size; ++i)
        nonce[i] = static_cast<char>(QRandomGenerator::global()->bounded(256));
    return nonce;
}


// ─────────────────────────────────────────────────────────────────────────────
// TLS 세션 열기
//
// 시나리오 A (최초 — 로컬 키 없음):
//   1. ML-DSA 키쌍 생성 → 앱 로컬 저장
//   2. PROVISION_DEVICE → Pi에 스마트폰 공개키 전송
//              ↳ Pi 공개키 + TLS 인증서 수신 → 로컬 저장
//   3. ML-DSA Challenge-Response 인증
//
// 시나리오 B (재접속 — 로컬 키 있음):
//   1. ML-DSA Challenge-Response 인증만 수행
// ─────────────────────────────────────────────────────────────────────────────

void AppController::openTlsSession(const QString &userId, const QString &piHostOrName)
{
    const QString trimmedUser = userId.trimmed();
    const QString trimmedHost = piHostOrName.trimmed();

    m_state.setTlsSessionStatus(QString());

    if (!m_authService.validateUser(trimmedUser)) {
        m_state.setTlsSessionStatus(QStringLiteral("아이디를 먼저 입력해주세요."));
        return;
    }
    if (trimmedHost.isEmpty()) {
        m_state.setTlsSessionStatus(QStringLiteral("Pi IP 또는 MagicDNS를 입력해주세요."));
        return;
    }

    m_state.setCurrentUser(trimmedUser);
    m_state.setCurrentPiHost(trimmedHost);
    m_state.setConnectionPhase(QStringLiteral("TLS 세션 초기화 중..."));
    m_state.setTerminalLog(QString());

    emit openConnectLoadingPage();
    QTimer::singleShot(0, this, &AppController::beginTlsSessionSequence);
}

void AppController::beginTlsSessionSequence()
{
    const QString userId = m_state.currentUser();
    const QString piHost = m_state.currentPiHost();
    QString errorMessage;

    const QString privKeyPath  = FileUtils::appPrivateKeyPathForUser(userId);
    const QString pubKeyPath   = FileUtils::appPublicKeyPathForUser(userId);
    const QString piPubPath    = FileUtils::trustedPiPublicKeyPathForUser(userId);
    const QString piCertPath   = FileUtils::trustedPiTlsCertPathForUser(userId);

    const bool hasLocalKeys = QFile::exists(privKeyPath) && QFile::exists(pubKeyPath);
    const bool hasTrustedPi = QFile::exists(piPubPath);

    // ── 시나리오 A: 최초 연결 — 키 생성 + Pi 등록 ──────────────────────────
    if (!hasLocalKeys || !hasTrustedPi) {

        // ─ 1단계: ML-DSA 키쌍 생성 ────────────────────────────────────────
        updateConnectionPhase(QStringLiteral("ML-DSA 키쌍 생성 중..."));
        appendTerminalLine(QStringLiteral("[APP] 스마트폰 ML-DSA 키쌍 생성 시작"));

        QString phonePublicKeyPem;
        if (!m_mldsaService.generateDeviceKeyPair(privKeyPath, pubKeyPath,
                                                   &phonePublicKeyPem, &errorMessage)) {
            m_state.setTlsSessionStatus(errorMessage.isEmpty()
                ? QStringLiteral("ML-DSA 키쌍 생성에 실패했습니다.")
                : errorMessage);
            emit backToConnectPage();
            return;
        }
        appendTerminalLine(QStringLiteral("[APP] 키쌍 생성 완료 → ") + pubKeyPath);

        // ─ 2단계: Pi에 공개키 전송 (TOFU 등록) — Pi 공개키 + TLS 인증서 수신
        updateConnectionPhase(QStringLiteral("Pi와 공개키 교환 중 (TOFU)..."));
        appendTerminalLine(QStringLiteral("[APP] Pi에 스마트폰 공개키 전송 (PROVISION_DEVICE)"));

        QString piPublicKeyPem;
        QString piTlsCertPem;
        if (!m_piGatewayService.provisionDevice(userId, piHost, phonePublicKeyPem,
                                                &piPublicKeyPem, &piTlsCertPem, &errorMessage)) {
            m_state.setTlsSessionStatus(errorMessage.isEmpty()
                ? QStringLiteral("Pi 공개키 등록에 실패했습니다.")
                : errorMessage);
            emit backToConnectPage();
            return;
        }

        // ─ 3단계: Pi 공개키 + TLS 인증서 로컬 저장 ───────────────────────
        if (!FileUtils::writeTextFile(piPubPath,  piPublicKeyPem, &errorMessage) ||
            !FileUtils::writeTextFile(piCertPath, piTlsCertPem,   &errorMessage)) {
            m_state.setTlsSessionStatus(QStringLiteral("Pi 키 저장 실패: ") + errorMessage);
            emit backToConnectPage();
            return;
        }
        appendTerminalLine(QStringLiteral("[APP] Pi 공개키 · TLS 인증서 저장 완료"));
    } else {
        appendTerminalLine(QStringLiteral("[APP] 저장된 키 확인 — Challenge-Response 인증 진행"));
    }

    // ── 공통: ML-DSA Challenge-Response 인증 ────────────────────────────────
    updateConnectionPhase(QStringLiteral("ML-DSA 서명 검증 중..."));
    appendTerminalLine(QStringLiteral("[APP] Challenge(nonce) 전송 시작"));

    // 저장된 Pi 공개키 로드
    const QString trustedPiPem = FileUtils::readTextFile(piPubPath, &errorMessage);
    if (trustedPiPem.isEmpty()) {
        m_state.setTlsSessionStatus(QStringLiteral("Pi 공개키를 읽을 수 없습니다."));
        emit backToConnectPage();
        return;
    }

    // nonce 생성 → Pi에 전송 → Pi 서명 수신
    const QByteArray nonce = generateRandomNonce(32);
    QByteArray piSignature;
    if (!m_piGatewayService.startAuthentication(userId, piHost, nonce,
                                                &piSignature, &errorMessage)) {
        m_state.setTlsSessionStatus(errorMessage.isEmpty()
            ? QStringLiteral("Pi 인증 요청에 실패했습니다.")
            : errorMessage);
        emit backToConnectPage();
        return;
    }

    // 수신한 서명을 저장된 Pi 공개키로 검증
    const QByteArray piPayload = buildPiAuthPayload(userId, nonce);
    if (!m_mldsaService.verifyMessage(trustedPiPem, piPayload, piSignature, &errorMessage)) {
        m_state.setTlsSessionStatus(errorMessage.isEmpty()
            ? QStringLiteral("Pi 서명 검증에 실패했습니다.")
            : errorMessage);
        emit backToConnectPage();
        return;
    }

    appendTerminalLine(QStringLiteral("[APP] ML-DSA 인증 성공 — TLS 채널 확보 완료"));

    // 서명값 앞 16바이트 hex (공백 없이 대문자 32자)
    const QString sigHex = QString::fromLatin1(piSignature.left(16).toHex()).toUpper();
    // 형식: "0x 3A9F D201 B4C8 E5F7 A210 9D3E C4D5 E6F7 ..."
    // 4자씩 공백 삽입해서 가독성 확보
    QString sigFormatted;
    for (int i = 0; i < sigHex.size(); i++) {
        if (i > 0 && i % 4 == 0) sigFormatted += QLatin1Char(' ');
        sigFormatted += sigHex[i];
    }
    m_state.setTlsSignaturePreview(
        QStringLiteral("0x ") + sigFormatted + QStringLiteral(" ..."));

    m_state.setTlsSessionStatus(QStringLiteral("TLS 채널 인증 완료 ✓  이제 로그인하세요."));
    emit tlsSessionReady();
}


// ─────────────────────────────────────────────────────────────────────────────
// 기존: 풀 로그인 시퀀스 (ID/PW + ML-DSA)
// ─────────────────────────────────────────────────────────────────────────────

bool AppController::connectToHsm(const QString &userId,
                                  const QString &password,
                                  const QString &piHostOrName)
{
    const QString trimmedUser = userId.trimmed();
    const QString trimmedHost = piHostOrName.trimmed();

    m_state.setStatusMessage(QString());

    if (!m_authService.validateUser(trimmedUser)) {
        m_state.setStatusMessage(QStringLiteral("아이디를 입력해주세요."));
        return false;
    }

    QString pwError;
    if (!m_authService.validatePassword(password, &pwError)) {
        m_state.setStatusMessage(pwError);
        return false;
    }

    if (trimmedHost.isEmpty()) {
        m_state.setStatusMessage(QStringLiteral("Pi Tailscale IP 또는 MagicDNS를 입력해주세요."));
        return false;
    }

    m_state.setCurrentUser(trimmedUser);
    m_state.setCurrentPiHost(trimmedHost);
    m_state.setConnectionPhase(QStringLiteral("ID/PW 인증 중..."));
    m_state.setTerminalLog(QString());
    m_pendingPassword = password;

    emit openConnectLoadingPage();
    QTimer::singleShot(0, this, &AppController::beginConnectionSequence);
    return true;
}

void AppController::beginConnectionSequence()
{
    const QString userId   = m_state.currentUser();
    const QString piHost   = m_state.currentPiHost();
    const QString password = m_pendingPassword;
    QString errorMessage;

    // 비밀번호 즉시 삭제 — fill 먼저, clear 나중
    m_pendingPassword.fill(QLatin1Char('0'));
    m_pendingPassword.clear();

    // ─ 0단계: ID/PW 검증 ────────────────────────────────────────────────────
    updateConnectionPhase(QStringLiteral("ID/PW 인증 중..."));
    appendTerminalLine(QStringLiteral("[APP] ID/PW 로그인 검증"));

    QString userRole;
    if (!m_piGatewayService.loginUser(userId, password, piHost, &errorMessage, &userRole)) {
        m_state.setStatusMessage(errorMessage.isEmpty()
            ? QStringLiteral("로그인에 실패했습니다.") : errorMessage);
        emit backToConnectPage();
        return;
    }
    m_state.setCurrentRole(userRole);   // 로그인 성공 시 역할 저장
    appendTerminalLine(QStringLiteral("[APP] ID/PW 검증 성공 (role: %1)").arg(userRole));

    // ─ 1단계: 저장된 Pi 공개키 확인 ─────────────────────────────────────────
    updateConnectionPhase(QStringLiteral("Pi 공개키 확인 중..."));
    appendTerminalLine(QStringLiteral("[APP] 저장된 Pi 공개키 확인"));

    const QString trustedPiPath = FileUtils::trustedPiPublicKeyPathForUser(userId);
    const QString trustedPiPem  = FileUtils::readTextFile(trustedPiPath, &errorMessage);
    if (trustedPiPem.isEmpty()) {
        m_state.setStatusMessage(
            QStringLiteral("저장된 Pi 공개키가 없습니다.\n먼저 'TLS 세션 열기'를 눌러 키를 등록해주세요."));
        emit backToConnectPage();
        return;
    }

    // ─ 2단계: ML-DSA Challenge-Response (세션이 이미 열려 있으면 건너뜀) ──────
    if (m_piGatewayService.hasActiveSession()) {
        // TLS 세션 열기에서 이미 인증 완료 — 재검증 불필요
        appendTerminalLine(QStringLiteral("[APP] TLS 세션 이미 인증됨 — ML-DSA 재검증 생략"));
    } else {
        updateConnectionPhase(QStringLiteral("ML-DSA 서명 검증 중..."));
        appendTerminalLine(QStringLiteral("[APP] Challenge(nonce) 전송"));

        const QByteArray nonce = generateRandomNonce(32);
        QByteArray piSignature;
        if (!m_piGatewayService.startAuthentication(userId, piHost, nonce,
                                                    &piSignature, &errorMessage)) {
            m_state.setStatusMessage(errorMessage);
            emit backToConnectPage();
            return;
        }

        const QByteArray piPayload = buildPiAuthPayload(userId, nonce);
        if (!m_mldsaService.verifyMessage(trustedPiPem, piPayload, piSignature, &errorMessage)) {
            m_state.setStatusMessage(errorMessage.isEmpty()
                ? QStringLiteral("Pi 서명 검증에 실패했습니다.") : errorMessage);
            emit backToConnectPage();
            return;
        }
        appendTerminalLine(QStringLiteral("[APP] ML-DSA 인증 성공 — 가상HSM 진위 확인 완료"));
    }
    finishConnect();
}

void AppController::finishConnect()
{
    m_state.setStatusMessage(QString());
    m_state.setConnectionPhase(QStringLiteral("인증 완료"));
    if (m_state.currentRole() == QStringLiteral("audit_user"))
        emit openAuditPage();
    else
        emit connectSuccess();
}


// ── 키 재발급 (기존) ────────────────────────────────────────────────────────

void AppController::goToRegeneratePage()                 { m_state.setRegenerateStatusMessage(QString()); emit openRegeneratePage(); }
void AppController::goBackToConnectPage()                { m_piGatewayService.closeSession(); m_state.setRegenerateStatusMessage(QString()); m_state.setLatestPublicKey(QString()); emit backToConnectPage(); }
void AppController::finishRegenerate()                   {}
void AppController::finishOperation()                    {}

void AppController::regeneratePublicKey(const QString &userId, const QString &piHostOrName)
{
    const QString trimmedUser = userId.trimmed();
    const QString trimmedHost = piHostOrName.trimmed();

    if (!m_authService.validateUser(trimmedUser)) { m_state.setRegenerateStatusMessage(QStringLiteral("유저명을 입력해주세요.")); return; }
    if (trimmedHost.isEmpty())                    { m_state.setRegenerateStatusMessage(QStringLiteral("Pi IP를 입력해주세요.")); return; }

    if (m_operationInProgress.exchange(true)) {
        m_state.setRegenerateStatusMessage(QStringLiteral("이전 작업이 진행 중입니다. 잠시 기다려주세요.")); return;
    }
    m_state.setRegenerateStatusMessage(QStringLiteral("키 재발급 중..."));
    QtConcurrent::run([this, trimmedUser, trimmedHost]() {
        const QString privateKeyPath = FileUtils::appPrivateKeyPathForUser(trimmedUser);
        const QString publicKeyPath  = FileUtils::appPublicKeyPathForUser(trimmedUser);
        QString phonePublicKeyPem, errorMessage;

        if (!m_mldsaService.generateDeviceKeyPair(privateKeyPath, publicKeyPath, &phonePublicKeyPem, &errorMessage)) {
            QMetaObject::invokeMethod(this, [this, errorMessage]() {
                m_operationInProgress = false;
                m_state.setRegenerateStatusMessage(errorMessage.isEmpty() ? QStringLiteral("키쌍 재발급 실패") : errorMessage);
            }, Qt::QueuedConnection);
            return;
        }
        QString piPublicKeyPem, piTlsCertPem;
        if (!m_piGatewayService.provisionDevice(trimmedUser, trimmedHost, phonePublicKeyPem, &piPublicKeyPem, &piTlsCertPem, &errorMessage)) {
            QMetaObject::invokeMethod(this, [this, errorMessage]() {
                m_operationInProgress = false;
                m_state.setRegenerateStatusMessage(errorMessage.isEmpty() ? QStringLiteral("Pi 등록 실패") : errorMessage);
            }, Qt::QueuedConnection);
            return;
        }
        if (!FileUtils::writeTextFile(FileUtils::trustedPiPublicKeyPathForUser(trimmedUser), piPublicKeyPem, &errorMessage) ||
            !FileUtils::writeTextFile(FileUtils::trustedPiTlsCertPathForUser(trimmedUser),  piTlsCertPem,   &errorMessage)) {
            QMetaObject::invokeMethod(this, [this, errorMessage]() {
                m_operationInProgress = false;
                m_state.setRegenerateStatusMessage(QStringLiteral("키 저장 실패: ") + errorMessage);
            }, Qt::QueuedConnection);
            return;
        }
        QMetaObject::invokeMethod(this, [this, publicKeyPath]() {
            m_operationInProgress = false;
            m_state.setLatestPublicKey(publicKeyPath);
            m_state.setRegenerateStatusMessage(QStringLiteral("공개키 재발급 및 Pi 등록이 완료되었습니다."));
        }, Qt::QueuedConnection);
    });
}


// ── 파일 / 암복호화 (기존) ──────────────────────────────────────────────────

void AppController::selectFile(const QString &path) { m_state.setSelectedFile(path); }

void AppController::uploadData()
{
    if (m_state.selectedFile().trimmed().isEmpty()) { m_state.setStatusMessage(QStringLiteral("파일 경로를 입력해주세요.")); return; }
    m_state.setStatusMessage(QStringLiteral("파일 업로드가 완료되었습니다."));
    emit openActionPage();
}

void AppController::startEncrypt()
{
    QString msg;
    if (!m_cryptoService.encrypt(m_state.selectedFile(), &msg)) { m_state.setStatusMessage(msg); return; }
    m_state.setStatusMessage(msg);
}

void AppController::startDecrypt()
{
    QString msg;
    if (!m_cryptoService.decrypt(m_state.selectedFile(), &msg)) { m_state.setStatusMessage(msg); return; }
    m_state.setStatusMessage(msg);
}

void AppController::startEncryptWithKey(const QString &keyNumber)
{
    if (m_operationInProgress.exchange(true)) {
        m_state.setStatusMessage(QStringLiteral("이전 작업이 진행 중입니다. 잠시 기다려주세요."));
        return;
    }

    const QString t = keyNumber.trimmed();
    if (t != QStringLiteral("1") && t != QStringLiteral("2") && t != QStringLiteral("3")) {
        m_operationInProgress = false;
        m_state.setStatusMessage(QStringLiteral("키 번호는 1, 2, 3 중 하나만 입력 가능합니다.")); return;
    }
    const QString filePath = m_state.selectedFile().trimmed();
    if (filePath.isEmpty()) {
        m_operationInProgress = false;
        m_state.setStatusMessage(QStringLiteral("먼저 이미지를 선택해주세요.")); return;
    }

    // 이미지 파일 읽기 → Base64 인코딩 (50MB 초과 차단)
    QFile f(filePath);
    constexpr qint64 kMaxFileSizeBytes = 50LL * 1024 * 1024;
    if (f.size() > kMaxFileSizeBytes) {
        m_operationInProgress = false;
        m_state.setStatusMessage(QStringLiteral("파일 크기가 50MB를 초과합니다.")); return;
    }
    if (!f.open(QIODevice::ReadOnly)) {
        m_operationInProgress = false;
        m_state.setStatusMessage(QStringLiteral("이미지 파일을 열 수 없습니다.")); return;
    }
    const QString imageB64 = QString::fromLatin1(f.readAll().toBase64());
    f.close();

    m_state.setStatusMessage(QStringLiteral("vHSM 암호화 처리 중..."));
    m_state.setCryptoResult(QString());
    m_state.setResultFilePath(QString());

    // 서버가 단일 스레드이므로 키 명령 전에 세션 닫기
    m_piGatewayService.closeSession();
    emit openWorkLoadingPage();

    const QString user   = m_state.currentUser();
    const QString host   = m_state.currentPiHost();
    const QString keyNum = t;
    // 결과 저장 경로: Pictures/<원본파일명>.enc
    const QString outPath = QStandardPaths::writableLocation(QStandardPaths::PicturesLocation)
                      + QStringLiteral("/") + QFileInfo(filePath).fileName() + QStringLiteral(".enc");

    // 워커 스레드에서 실행 — 메인 스레드 블로킹 없이 로딩 애니메이션 표시
    QtConcurrent::run([this, user, host, keyNum, imageB64, outPath]() {
        QString result, err;
        const bool ok = m_piGatewayService.sendKeyCommand(
            user, host, QStringLiteral("encrypt"), keyNum, imageB64, &result, &err);

        QMetaObject::invokeMethod(this, [this, ok, result, err, outPath]() {
            m_operationInProgress = false;
            if (!ok) {
                m_state.setStatusMessage(err.isEmpty() ? QStringLiteral("암호화 실패") : err);
            } else {
                QFile out(outPath);
                QDir().mkpath(QFileInfo(outPath).absolutePath());
                if (out.open(QIODevice::WriteOnly | QIODevice::Text)) {
                    out.write(result.toUtf8());
                    out.close();
                    m_state.setStatusMessage(QStringLiteral("데이터 암호화 완료!"));
                    m_state.setResultFilePath(outPath);
                    m_state.setCryptoResult(result.left(32) + QStringLiteral("..."));
                } else {
                    m_state.setStatusMessage(QStringLiteral("암호화 성공, 파일 저장 실패: ") + outPath);
                }
            }
            emit operationFinished();
        }, Qt::QueuedConnection);
    });
}

void AppController::startDecryptWithKey(const QString &keyNumber)
{
    if (m_operationInProgress.exchange(true)) {
        m_state.setStatusMessage(QStringLiteral("이전 작업이 진행 중입니다. 잠시 기다려주세요."));
        return;
    }

    const QString t = keyNumber.trimmed();
    if (t != QStringLiteral("1") && t != QStringLiteral("2") && t != QStringLiteral("3")) {
        m_operationInProgress = false;
        m_state.setStatusMessage(QStringLiteral("키 번호는 1, 2, 3 중 하나만 입력 가능합니다.")); return;
    }
    const QString filePath = m_state.selectedFile().trimmed();
    if (filePath.isEmpty()) {
        m_operationInProgress = false;
        m_state.setStatusMessage(QStringLiteral("먼저 .enc 파일을 선택해주세요.")); return;
    }

    // .enc 파일 읽기 → "<ciphertext_hex>:<iv_hex>"
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        m_operationInProgress = false;
        m_state.setStatusMessage(QStringLiteral(".enc 파일을 열 수 없습니다.")); return;
    }
    const QString data = QString::fromUtf8(f.readAll()).trimmed();
    f.close();

    m_state.setStatusMessage(QStringLiteral("vHSM 복호화 처리 중..."));
    m_state.setCryptoResult(QString());
    m_state.setResultFilePath(QString());

    // 서버가 단일 스레드이므로 키 명령 전에 세션 닫기
    m_piGatewayService.closeSession();
    emit openWorkLoadingPage();

    const QString user   = m_state.currentUser();
    const QString host   = m_state.currentPiHost();
    const QString keyNum = t;
    // 결과 저장 경로: Pictures/<원본파일명 (.enc 제거)>_decrypted
    QString baseName = QFileInfo(filePath).fileName();
    if (baseName.endsWith(QStringLiteral(".enc")))
        baseName = baseName.left(baseName.length() - 4);
    const int dotPos = baseName.lastIndexOf('.');
    const QString outPath = QStandardPaths::writableLocation(QStandardPaths::PicturesLocation)
                      + QStringLiteral("/")
                      + (dotPos >= 0
                         ? baseName.left(dotPos) + QStringLiteral("_decrypted") + baseName.mid(dotPos)
                         : baseName + QStringLiteral("_decrypted"));

    // 워커 스레드에서 실행 — 메인 스레드 블로킹 없이 로딩 애니메이션 표시
    QtConcurrent::run([this, user, host, keyNum, data, outPath]() {
        QString result, err;
        const bool ok = m_piGatewayService.sendKeyCommand(
            user, host, QStringLiteral("decrypt"), keyNum, data, &result, &err);

        QMetaObject::invokeMethod(this, [this, ok, result, err, outPath]() {
            m_operationInProgress = false;
            if (!ok) {
                m_state.setStatusMessage(err.isEmpty() ? QStringLiteral("복호화 실패") : err);
            } else {
                const QByteArray imageBytes = QByteArray::fromBase64(result.toLatin1());
                QFile out(outPath);
                QDir().mkpath(QFileInfo(outPath).absolutePath());
                if (out.open(QIODevice::WriteOnly)) {
                    out.write(imageBytes);
                    out.close();
                    m_state.setStatusMessage(QStringLiteral("데이터 복호화 완료!"));
                    m_state.setResultFilePath(outPath);
                    m_state.setCryptoResult(QStringLiteral("복호화된 이미지가 저장되었습니다."));
                } else {
                    m_state.setStatusMessage(QStringLiteral("복호화 성공, 파일 저장 실패: ") + outPath);
                }
            }
            emit operationFinished();
        }, Qt::QueuedConnection);
    });
}


// ── 페이지 네비게이션 ────────────────────────────────────────────────────────

void AppController::goToSignUpPage(const QString &piHostOrName) {
    if (!piHostOrName.trimmed().isEmpty()) m_state.setCurrentPiHost(piHostOrName.trimmed());
    m_state.setSignUpStatusMessage(QString());
    emit openSignUpPage();
}
void AppController::goToFindIdPage(const QString &piHostOrName) {
    if (!piHostOrName.trimmed().isEmpty()) m_state.setCurrentPiHost(piHostOrName.trimmed());
    m_state.setFindIdStatusMessage(QString());
    emit openFindIdPage();
}
void AppController::goToFindPasswordPage() { m_state.setFindPasswordStatusMessage(QString()); emit openFindPasswordPage(); }


// ── 회원가입 ────────────────────────────────────────────────────────────────

// ── 초대 코드로 회원가입 ──────────────────────────────────────────────────────
void AppController::signUpWithInvite(const QString &id, const QString &password,
                                      const QString &passwordConfirm,
                                      const QString &name, const QString &email,
                                      const QString &inviteCode)
{
    if (id.trimmed().isEmpty() || name.trimmed().isEmpty()) {
        m_state.setSignUpStatusMessage(QStringLiteral("아이디와 이름은 필수 입력 항목입니다.")); return;
    }
    if (inviteCode.trimmed().isEmpty()) {
        m_state.setSignUpStatusMessage(QStringLiteral("초대 코드를 입력해주세요.")); return;
    }
    QString pwError;
    if (!m_authService.validatePassword(password, &pwError)) { m_state.setSignUpStatusMessage(pwError); return; }
    if (!m_authService.passwordsMatch(password, passwordConfirm, &pwError)) { m_state.setSignUpStatusMessage(pwError); return; }
    const QString piHost = m_state.currentPiHost();
    if (piHost.isEmpty()) { m_state.setSignUpStatusMessage(QStringLiteral("Pi IP가 설정되지 않았습니다.")); return; }

    if (m_operationInProgress.exchange(true)) {
        m_state.setSignUpStatusMessage(QStringLiteral("이전 작업이 진행 중입니다. 잠시 기다려주세요.")); return;
    }
    m_state.setSignUpStatusMessage(QStringLiteral("가입 처리 중..."));
    const QString capCode  = inviteCode.trimmed().toUpper();
    const QString capId    = id.trimmed();
    const QString capPw    = password;
    const QString capName  = name.trimmed();
    const QString capEmail = email.trimmed();
    QtConcurrent::run([this, capCode, capId, capPw, capName, capEmail, piHost]() {
        QString err;
        const bool ok = m_piGatewayService.registerWithInvite(capCode, capId, capPw, capName, capEmail, piHost, &err);
        QMetaObject::invokeMethod(this, [this, ok, err]() {
            m_operationInProgress = false;
            m_state.setSignUpStatusMessage(ok
                ? QStringLiteral("가입 완료!\n로그인 후 'TLS 세션 열기'를 눌러 키를 등록해주세요.")
                : (err.isEmpty() ? QStringLiteral("가입 실패") : err));
        }, Qt::QueuedConnection);
    });
}


// ── 아이디 찾기 ─────────────────────────────────────────────────────────────

void AppController::requestAuditLog()
{
    const QString piHost = m_state.currentPiHost();
    if (piHost.isEmpty()) {
        m_state.setAuditLogJson(QStringLiteral("[]"));
        return;
    }
    QString logJson, err;
    if (m_piGatewayService.getAuditLog(m_state.currentUser(), piHost, &logJson, &err)) {
        m_state.setAuditLogJson(logJson);
    } else {
        m_state.setAuditLogJson(QStringLiteral("[]"));
        if (err == QStringLiteral("SESSION_EXPIRED")) {
            m_state.setStatusMessage(QStringLiteral("세션이 만료되었습니다. 다시 로그인해주세요."));
            emit backToConnectPage();
        } else {
            m_state.setStatusMessage(err.isEmpty()
                ? QStringLiteral("감사 로그를 불러올 수 없습니다.")
                : err);
        }
    }
}

void AppController::findId(const QString &name)
{
    if (name.trimmed().isEmpty()) { m_state.setFindIdStatusMessage(QStringLiteral("이름을 입력해주세요.")); return; }
    const QString piHost = m_state.currentPiHost();
    if (piHost.isEmpty()) { m_state.setFindIdStatusMessage(QStringLiteral("Pi IP가 설정되지 않았습니다.")); return; }
    if (m_operationInProgress.exchange(true)) {
        m_state.setFindIdStatusMessage(QStringLiteral("이전 작업이 진행 중입니다. 잠시 기다려주세요.")); return;
    }
    m_state.setFindIdStatusMessage(QStringLiteral("검색 중..."));
    const QString capName = name.trimmed();
    QtConcurrent::run([this, capName, piHost]() {
        QString foundId, err;
        const bool ok = m_piGatewayService.findUserId(capName, piHost, &foundId, &err);
        QMetaObject::invokeMethod(this, [this, ok, foundId, err]() {
            m_operationInProgress = false;
            m_state.setFindIdStatusMessage(ok
                ? QStringLiteral("회원님의 아이디: %1").arg(foundId)
                : (err.isEmpty() ? QStringLiteral("일치하는 계정을 찾을 수 없습니다.") : err));
        }, Qt::QueuedConnection);
    });
}


// ── 비밀번호 찾기 ────────────────────────────────────────────────────────────

void AppController::findPassword(const QString &name, const QString &id)
{
    if (name.trimmed().isEmpty() || id.trimmed().isEmpty()) {
        m_state.setFindPasswordStatusMessage(QStringLiteral("이름과 아이디를 모두 입력해주세요.")); return;
    }
    const QString piHost = m_state.currentPiHost();
    if (piHost.isEmpty()) { m_state.setFindPasswordStatusMessage(QStringLiteral("Pi IP가 설정되지 않았습니다.")); return; }
    if (m_operationInProgress.exchange(true)) {
        m_state.setFindPasswordStatusMessage(QStringLiteral("이전 작업이 진행 중입니다. 잠시 기다려주세요.")); return;
    }
    m_state.setFindPasswordStatusMessage(QStringLiteral("확인 중..."));
    const QString capId   = id.trimmed();
    const QString capName = name.trimmed();
    QtConcurrent::run([this, capId, capName, piHost]() {
        QString err;
        const bool ok = m_piGatewayService.findPasswordCheck(capId, capName, piHost, &err);
        QMetaObject::invokeMethod(this, [this, ok, capId, err]() {
            m_operationInProgress = false;
            if (!ok) {
                m_state.setFindPasswordStatusMessage(err.isEmpty() ? QStringLiteral("일치하는 계정을 찾을 수 없습니다.") : err);
                return;
            }
            m_state.setPendingResetUserId(capId);
            m_state.setFindPasswordStatusMessage(QStringLiteral("계정이 확인되었습니다."));
            emit openResetPasswordPage();
        }, Qt::QueuedConnection);
    });
}


// ── 비밀번호 재설정 ──────────────────────────────────────────────────────────

void AppController::resetPassword(const QString &password, const QString &passwordConfirm)
{
    QString pwError;
    if (!m_authService.validatePassword(password, &pwError)) { m_state.setResetPasswordStatusMessage(pwError); return; }
    if (!m_authService.passwordsMatch(password, passwordConfirm, &pwError)) { m_state.setResetPasswordStatusMessage(pwError); return; }
    const QString targetUser = m_state.pendingResetUserId();
    if (targetUser.isEmpty()) { m_state.setResetPasswordStatusMessage(QStringLiteral("재설정 대상 정보가 없습니다. 처음부터 다시 시도하세요.")); return; }
    const QString piHost = m_state.currentPiHost();
    if (piHost.isEmpty()) { m_state.setResetPasswordStatusMessage(QStringLiteral("Pi IP가 설정되지 않았습니다.")); return; }
    if (m_operationInProgress.exchange(true)) {
        m_state.setResetPasswordStatusMessage(QStringLiteral("이전 작업이 진행 중입니다. 잠시 기다려주세요.")); return;
    }
    m_state.setResetPasswordStatusMessage(QStringLiteral("재설정 중..."));
    const QString capPw = password;
    QtConcurrent::run([this, targetUser, capPw, piHost]() {
        QString err;
        const bool ok = m_piGatewayService.resetPassword(targetUser, capPw, piHost, &err);
        QMetaObject::invokeMethod(this, [this, ok, err]() {
            m_operationInProgress = false;
            if (!ok) {
                m_state.setResetPasswordStatusMessage(err.isEmpty() ? QStringLiteral("비밀번호 재설정 실패") : err);
                return;
            }
            m_state.setPendingResetUserId(QString());
            m_state.setResetPasswordStatusMessage(QStringLiteral("비밀번호가 재설정되었습니다. 새 비밀번호로 로그인해주세요."));
        }, Qt::QueuedConnection);
    });
}
