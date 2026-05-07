import QtQuick
import QtQuick.Controls
import "../components"
import "../styles" 1.0

// HSM 최초 초기화 페이지 — DB가 비어있을 때만 접근 가능
// Root Officer 계정을 생성하고 이후 모든 슬롯/유저 관리를 담당하게 됨
Page {
    property var stackViewRef
    background: Rectangle { color: "#f7f7f7" }

    Column {
        anchors.fill: parent
        spacing: 0

        AppHeader {
            showBackButton: true
            onBackClicked: appController.goBackToConnectPage()
        }

        Flickable {
            width: parent.width
            height: parent.height - 84
            contentHeight: innerColumn.height + 40
            clip: true

            Column {
                id: innerColumn
                anchors.horizontalCenter: parent.horizontalCenter
                topPadding: 48
                spacing: 6

                // ── 타이틀 ────────────────────────────────────────────────
                Text {
                    text: "HSM 초기화"
                    font.family: Theme.fontFamily
                    font.pixelSize: 22
                    font.bold: true
                    color: "#111111"
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Text {
                    text: "최초 Root Officer 계정을 생성합니다"
                    font.family: Theme.fontFamily
                    font.pixelSize: 13
                    color: "#c0392b"
                    font.bold: true
                    anchors.horizontalCenter: parent.horizontalCenter
                    bottomPadding: 20
                }

                // ── 아이디 ────────────────────────────────────────────────
                Text { text: "아이디"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333333"; leftPadding: 4 }
                AppTextField {
                    id: idField
                    placeholderText: ""
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 8 }

                // ── 비밀번호 ──────────────────────────────────────────────
                Text { text: "비밀번호"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333333"; leftPadding: 4 }
                AppTextField {
                    id: pwField
                    placeholderText: ""
                    echoMode: TextInput.Password
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 8 }

                // ── 비밀번호 확인 ─────────────────────────────────────────
                Text { text: "비밀번호 확인"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333333"; leftPadding: 4 }
                AppTextField {
                    id: pwConfirmField
                    placeholderText: ""
                    echoMode: TextInput.Password
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 8 }

                // ── 이름 ──────────────────────────────────────────────────
                Text { text: "이름"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333333"; leftPadding: 4 }
                AppTextField {
                    id: nameField
                    placeholderText: ""
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 8 }

                // ── 이메일 (선택) ─────────────────────────────────────────
                Text { text: "이메일 (선택)"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333333"; leftPadding: 4 }
                AppTextField {
                    id: emailField
                    placeholderText: "@"
                    inputMethodHints: Qt.ImhEmailCharactersOnly
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 20 }

                AppButton {
                    text: "HSM 초기화 및 Root Officer 생성"
                    onClicked: appController.bootstrapRootOfficer(
                        idField.text, pwField.text, pwConfirmField.text,
                        nameField.text, emailField.text
                    )
                }

                Text {
                    text: appController.signUpStatusMessage
                    visible: text.length > 0
                    color: text.indexOf("생성") >= 0 ? "green" : "red"
                    font.family: Theme.fontFamily
                    font.pixelSize: 12
                    width: 300
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    anchors.horizontalCenter: parent.horizontalCenter
                }
            }
        }
    }
}
