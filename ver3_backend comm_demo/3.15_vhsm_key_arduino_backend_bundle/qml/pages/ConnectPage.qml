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
                text: "가상 HSM 접속하기"
                font.family: Theme.fontFamily
                font.pixelSize: 20
                font.bold: true
                color: "#111111"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Text {
                text: "접속하려면 유저명을 입력하세요"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#444444"
                anchors.horizontalCenter: parent.horizontalCenter
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

            AppTextField {
                id: piHostField
                placeholderText: "Pi Tailscale IP 또는 MagicDNS 입력"
                text: "100.114.157.74"
                leftPadding: 14
                rightPadding: 14
                topPadding: 0
                bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            AppButton {
                text: "가상HSM 접속하기"
                onClicked: appController.connectToHsm(userField.text, piHostField.text)
            }

            Text {
                text: "기본 세팅값: 100.114.157.74"
                font.family: Theme.fontFamily
                font.pixelSize: 11
                color: "#666666"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Text {
                text: appController.statusMessage
                visible: text.length > 0
                color: "red"
                font.family: Theme.fontFamily
                font.pixelSize: 12
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Item { width: 1; height: 28 }

            Text {
                text: "접속에 문제가 있으신가요?"
                font.family: Theme.fontFamily
                font.pixelSize: 15
                color: "#333333"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Text {
                text: "인증 키 전체 초기화 및 재발급하기"
                font.family: Theme.fontFamily
                font.pixelSize: 14
                color: "#7a7a7a"
                anchors.horizontalCenter: parent.horizontalCenter
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: appController.goToRegeneratePage()
                }
            }
        }
    }
}
