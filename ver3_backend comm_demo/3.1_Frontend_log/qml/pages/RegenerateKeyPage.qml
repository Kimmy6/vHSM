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
            topPadding: 80
            spacing: 18

            Text {
                text: "공개 키 재발급하기"
                font.family: Theme.fontFamily
                font.pixelSize: 20
                font.bold: true
                color: "#111111"
            }

            Text {
                text: "재발급하려면 유저명을 입력하세요"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#444444"
            }

            AppTextField {
                id: userField
                placeholderText: "유저명 입력"
                leftPadding: 14
                rightPadding: 14
                topPadding: 0
                bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            AppButton {
                text: "공개 키 재발급하기"
                onClicked: appController.regeneratePublicKey(userField.text)
            }

            Text {
                text: appController.statusMessage
                visible: text.length > 0
                color: appController.statusMessage.indexOf("regenerated") >= 0 ? "green" : "red"
                font.family: Theme.fontFamily
                font.pixelSize: 12
            }
        }
    }
}
