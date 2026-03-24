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
            topPadding: 56
            spacing: 18

            Text {
                text: "안녕하세요, " + (appController.currentUser.length > 0 ? appController.currentUser : "User") + " 님."
                font.family: Theme.fontFamily
                font.pixelSize: 18
                font.bold: true
                color: "#111111"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            AppTextField {
                id: keyNumberField
                placeholderText: "키 번호 입력"
                leftPadding: 14
                rightPadding: 14
                topPadding: 0
                bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            AppButton {
                text: "암호화 하기"
                onClicked: appController.startEncryptWithKey(keyNumberField.text)
            }

            AppButton {
                text: "복호화 하기"
                onClicked: appController.startDecryptWithKey(keyNumberField.text)
            }

            Text {
                text: appController.statusMessage
                visible: text.length > 0
                color: "#444444"
                font.family: Theme.fontFamily
                font.pixelSize: 12
                width: 260
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }
        }
    }
}