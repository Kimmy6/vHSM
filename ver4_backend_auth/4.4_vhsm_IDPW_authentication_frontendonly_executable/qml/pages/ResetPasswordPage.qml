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

        Column {
            anchors.horizontalCenter: parent.horizontalCenter
            topPadding: 72
            spacing: 16

            Text {
                text: "패스워드 초기화"
                font.family: Theme.fontFamily
                font.pixelSize: 22
                font.bold: true
                color: "#111111"
                anchors.horizontalCenter: parent.horizontalCenter
                bottomPadding: 16
            }

            Text {
                text: "비밀번호"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#333333"
                leftPadding: 4
            }

            AppTextField {
                id: newPwField
                placeholderText: ""
                echoMode: TextInput.Password
                leftPadding: 14; rightPadding: 14
                topPadding: 0; bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            Item { width: 1; height: 4 }

            Text {
                text: "비밀번호 확인"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#333333"
                leftPadding: 4
            }

            AppTextField {
                id: newPwConfirmField
                placeholderText: ""
                echoMode: TextInput.Password
                leftPadding: 14; rightPadding: 14
                topPadding: 0; bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            Item { width: 1; height: 8 }

            AppButton {
                text: "비밀번호 재설정하기"
                onClicked: appController.resetPassword(newPwField.text, newPwConfirmField.text)
            }

            Text {
                text: appController.resetPasswordStatusMessage
                visible: text.length > 0
                color: text.indexOf("완료") >= 0 || text.indexOf("성공") >= 0 ? "green" : "red"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                width: 300
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }
        }
    }
}
