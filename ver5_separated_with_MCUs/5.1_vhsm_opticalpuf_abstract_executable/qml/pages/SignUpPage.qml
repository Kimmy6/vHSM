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

                Text {
                    text: "회원 가입하기"
                    font.family: Theme.fontFamily
                    font.pixelSize: 22
                    font.bold: true
                    color: "#111111"
                    anchors.horizontalCenter: parent.horizontalCenter
                    bottomPadding: 20
                }

                // 아이디
                Text {
                    text: "아이디"
                    font.family: Theme.fontFamily
                    font.pixelSize: 13
                    color: "#333333"
                    leftPadding: 4
                }
                AppTextField {
                    id: signUpIdField
                    placeholderText: ""
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 8 }

                // 비밀번호
                Text {
                    text: "비밀번호"
                    font.family: Theme.fontFamily
                    font.pixelSize: 13
                    color: "#333333"
                    leftPadding: 4
                }
                AppTextField {
                    id: signUpPwField
                    placeholderText: ""
                    echoMode: TextInput.Password
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 8 }

                // 비밀번호 확인
                Text {
                    text: "비밀번호 확인"
                    font.family: Theme.fontFamily
                    font.pixelSize: 13
                    color: "#333333"
                    leftPadding: 4
                }
                AppTextField {
                    id: signUpPwConfirmField
                    placeholderText: ""
                    echoMode: TextInput.Password
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 8 }

                // 이름
                Text {
                    text: "이름"
                    font.family: Theme.fontFamily
                    font.pixelSize: 13
                    color: "#333333"
                    leftPadding: 4
                }
                AppTextField {
                    id: signUpNameField
                    placeholderText: ""
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 8 }

                // 이메일
                Text {
                    text: "이메일"
                    font.family: Theme.fontFamily
                    font.pixelSize: 13
                    color: "#333333"
                    leftPadding: 4
                }
                AppTextField {
                    id: signUpEmailField
                    placeholderText: "@"
                    inputMethodHints: Qt.ImhEmailCharactersOnly
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                Item { width: 1; height: 20 }

                AppButton {
                    text: "회원 가입하기"
                    onClicked: appController.signUp(
                        signUpIdField.text,
                        signUpPwField.text,
                        signUpPwConfirmField.text,
                        signUpNameField.text,
                        signUpEmailField.text
                    )
                }

                Text {
                    text: appController.signUpStatusMessage
                    visible: text.length > 0
                    color: text.indexOf("완료") >= 0 || text.indexOf("성공") >= 0 ? "green" : "red"
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
