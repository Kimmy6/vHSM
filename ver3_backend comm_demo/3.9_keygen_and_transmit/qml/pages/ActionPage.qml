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
            spacing: 24

            Text {
                text: "수행할 항목을 선택해주세요"
                font.family: Theme.fontFamily
                font.pixelSize: 20
                font.bold: true
                color: "#111111"
            }

            AppButton {
                text: "암호화 하기"
                onClicked: appController.startEncrypt()
            }

            AppButton {
                text: "복호화 하기"
                onClicked: appController.startDecrypt()
            }

            Text {
                text: appController.statusMessage
                visible: text.length > 0
                color: appController.statusMessage.indexOf("complete") >= 0 ? "green" : "#555555"
                font.family: Theme.fontFamily
                font.pixelSize: 12
            }
        }
    }
}
