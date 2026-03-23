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
            spacing: 22

            Text {
                text: "가상 HSM 접속 중..."
                font.family: Theme.fontFamily
                font.pixelSize: 20
                font.bold: true
                color: "#111111"
            }

            Text {
                text: "잠시만 기다려주세요..."
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#555555"
            }

            LoadingSpinner { anchors.horizontalCenter: parent.horizontalCenter }
        }
    }
}
