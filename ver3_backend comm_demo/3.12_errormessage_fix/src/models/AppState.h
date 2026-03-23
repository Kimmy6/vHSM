void AppController::startEncryptWithKey(const QString &keyNumber)
{
    const QString trimmed = keyNumber.trimmed();
    if (trimmed != "1" && trimmed != "2" && trimmed != "3") {
        m_state.setStatusMessage(QStringLiteral("키 번호는 1, 2, 3 중 하나만 입력 가능합니다."));
        return;
    }

    QString errorMessage;
    if (!m_piGatewayService.sendKeyCommand(m_state.currentUser(),
                                           QStringLiteral("encrypt"),
                                           trimmed,
                                           &errorMessage)) {
        m_state.setStatusMessage(errorMessage.isEmpty()
                                 ? QStringLiteral("암호화 명령 전송에 실패했습니다.")
                                 : errorMessage);
        return;
    }

    m_state.setStatusMessage(QStringLiteral("암호화 명령을 전송했습니다. (키 %1)").arg(trimmed));
}

void AppController::startDecryptWithKey(const QString &keyNumber)
{
    const QString trimmed = keyNumber.trimmed();
    if (trimmed != "1" && trimmed != "2" && trimmed != "3") {
        m_state.setStatusMessage(QStringLiteral("키 번호는 1, 2, 3 중 하나만 입력 가능합니다."));
        return;
    }

    QString errorMessage;
    if (!m_piGatewayService.sendKeyCommand(m_state.currentUser(),
                                           QStringLiteral("decrypt"),
                                           trimmed,
                                           &errorMessage)) {
        m_state.setStatusMessage(errorMessage.isEmpty()
                                 ? QStringLiteral("복호화 명령 전송에 실패했습니다.")
                                 : errorMessage);
        return;
    }

    m_state.setStatusMessage(QStringLiteral("복호화 명령을 전송했습니다. (키 %1)").arg(trimmed));
}