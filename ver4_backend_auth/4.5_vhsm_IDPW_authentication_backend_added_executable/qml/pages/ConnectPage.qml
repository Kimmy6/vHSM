import QtQuick
import QtQuick.Controls
import "../components"
import "../styles" 1.0

Page {
    property var stackViewRef
    background: Rectangle { color: "#f7f7f7" }

    Column {
        anchors.fill: parent
        spacing: 0

        AppHeader {}

        Column {
            anchors.horizontalCenter: parent.horizontalCenter
            topPadding: 60
            spacing: 16

            // ── 타이틀 ───────────────────────────────────────────────────
            Text {
                text: "가상 HSM 접속하기"
                font.family: Theme.fontFamily
                font.pixelSize: 20
                font.bold: true
                color: "#111111"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Text {
                text: "접속하려면 아이디와 비밀번호를 입력하세요"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#444444"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Item { width: 1; height: 8 }

            // ── 아이디 / 비밀번호 ────────────────────────────────────────
            AppTextField {
                id: idField
                placeholderText: "아이디 입력"
                leftPadding: 14; rightPadding: 14
                topPadding: 0; bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            AppTextField {
                id: passwordField
                placeholderText: "비밀번호 입력"
                echoMode: TextInput.Password
                leftPadding: 14; rightPadding: 14
                topPadding: 0; bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            // ── Pi IP + TLS 세션 열기 (Row 레이아웃) ────────────────────
            // 전체 폭 300px = IP 필드 176px + 간격 8px + 버튼 116px
            Row {
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: 8

                // Pi IP 입력 필드
                AppTextField {
                    id: piHostField
                    width: 176
                    height: 48
                    placeholderText: "Pi IP / MagicDNS"
                    text: "100.114.157.74"
                    leftPadding: 10; rightPadding: 10
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                    font.pixelSize: 12
                }

                // TLS 세션 열기 버튼
                Button {
                    width: 116
                    height: 48

                    background: Rectangle {
                        radius: 8
                        // 인증 완료 시 녹색, 기본은 진회색
                        color: tlsReady ? "#1a7a4a" : "#2c2c2c"
                        Behavior on color { ColorAnimation { duration: 300 } }
                    }

                    // tlsSessionStatus에 "완료" 포함되면 인증 완료 상태로 간주
                    property bool tlsReady: appController.tlsSessionStatus.indexOf("완료") >= 0

                    contentItem: Column {
                        anchors.centerIn: parent
                        spacing: 2

                        // TLS 세션 버튼
                        Text {
                            text: parent.parent.tlsReady ? "TLS 세션 동작 중" : "TLS 세션 열기"
                            font.pixelSize: 14
                            anchors.horizontalCenter: parent.horizontalCenter
                        }
                    }

                    onClicked: appController.openTlsSession(idField.text, piHostField.text)
                }
            }

            // ── TLS 세션 상태 메시지 ──────────────────────────────────────
            Text {
                id: tlsStatusText
                text: appController.tlsSessionStatus
                visible: text.length > 0
                // "완료"·"성공" 포함이면 초록, 아니면 빨간
                color: text.indexOf("완료") >= 0 || text.indexOf("성공") >= 0
                       ? "#1a7a4a" : "#cc0000"
                font.family: Theme.fontFamily
                font.pixelSize: 12
                width: 300
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }

            // ── 접속 버튼 ────────────────────────────────────────────────
            AppButton {
                text: "가상HSM 접속하기"
                onClicked: appController.connectToHsm(idField.text, passwordField.text, piHostField.text)
            }

            // ── 로그인 오류 메시지 ───────────────────────────────────────
            Text {
                text: appController.statusMessage
                visible: text.length > 0
                color: "#cc0000"
                font.family: Theme.fontFamily
                font.pixelSize: 12
                width: 300
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Item { width: 1; height: 16 }

            // ── 보조 링크 ────────────────────────────────────────────────
            Text {
                text: "접속에 문제가 있으신가요?"
                font.family: Theme.fontFamily
                font.pixelSize: 15
                color: "#333333"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Row {
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: 20

                Text {
                    text: "새 계정 만들기"
                    font.family: Theme.fontFamily
                    font.pixelSize: 14
                    color: "#7a7a7a"
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: appController.goToSignUpPage(piHostField.text)
                    }
                }

                Text {
                    text: "|"
                    font.pixelSize: 14
                    color: "#cccccc"
                }

                Text {
                    text: "아이디, 비밀번호 찾기"
                    font.family: Theme.fontFamily
                    font.pixelSize: 14
                    color: "#7a7a7a"
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: appController.goToFindIdPage(piHostField.text)
                    }
                }
            }
        }
    }
}
