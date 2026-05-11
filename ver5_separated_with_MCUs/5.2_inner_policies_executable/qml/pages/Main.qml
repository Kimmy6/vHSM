import QtQuick
import QtQuick.Controls
import QtQml
import "pages"
import "styles" 1.0

ApplicationWindow {
    id: window
    width: 390
    height: 844
    visible: true
    title: "PNU Virtual HSM"
    color: "#f7f7f7"
    font.family: Theme.fontFamily

    StackView {
        id: stackView
        anchors.fill: parent
        initialItem: ConnectPage { stackViewRef: stackView }
    }

    Connections {
        target: appController

        // ── 풀 접속 플로우 ─────────────────────────────────────────────
        function onOpenConnectLoadingPage() {
            stackView.push(Qt.resolvedUrl("pages/ConnectLoadingPage.qml"), { "stackViewRef": stackView })
        }

        function onConnectSuccess() {
            stackView.clear()
            stackView.push(Qt.resolvedUrl("pages/DataLoadingPage.qml"), { "stackViewRef": stackView })
        }

        function onBackToConnectPage() {
            stackView.clear()
            stackView.push(Qt.resolvedUrl("pages/ConnectPage.qml"), { "stackViewRef": stackView })
        }

        function onOpenActionPage() {
            stackView.push(Qt.resolvedUrl("pages/ActionPage.qml"), { "stackViewRef": stackView })
        }

        function onOpenWorkLoadingPage() {
            stackView.push(Qt.resolvedUrl("pages/WorkLoadingPage.qml"), { "stackViewRef": stackView })
        }

        function onOperationFinished() {
            // WorkLoadingPage 하나만 pop → ActionPage로 복귀
            if (stackView.depth > 1)
                stackView.pop()
        }

        // ── TLS 세션 열기 성공 ────────────────────────────────────────
        // ConnectLoadingPage만 pop → 기존 ConnectPage로 복귀 (입력값 유지)
        function onTlsSessionReady() {
            stackView.pop()
        }

        // ── 키 재발급 ─────────────────────────────────────────────────
        function onOpenRegeneratePage() {
            stackView.push(Qt.resolvedUrl("pages/RegenerateKeyPage.qml"), { "stackViewRef": stackView })
        }

        // ── 회원가입 / 계정 찾기 ──────────────────────────────────────
        function onOpenSignUpPage() {
            stackView.push(Qt.resolvedUrl("pages/SignUpPage.qml"), { "stackViewRef": stackView })
        }

        function onOpenFindIdPage() {
            stackView.push(Qt.resolvedUrl("pages/FindIdPage.qml"), { "stackViewRef": stackView })
        }

        function onOpenFindPasswordPage() {
            stackView.push(Qt.resolvedUrl("pages/FindPasswordPage.qml"), { "stackViewRef": stackView })
        }

        function onOpenResetPasswordPage() {
            stackView.push(Qt.resolvedUrl("pages/ResetPasswordPage.qml"), { "stackViewRef": stackView })
        }
    }
}
