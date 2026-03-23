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
                text: "공개 키 재발급하기"
                onClicked: appController.regeneratePublicKey(userField.text, piHostField.text)
            }

            Text {
                text: appController.regenerateStatusMessage
                visible: text.length > 0
                color: text.indexOf("완료") >= 0 ? "green" : "red"
                font.family: Theme.fontFamily
                font.pixelSize: 12
                width: 280
                wrapMode: Text.WordWrap
            }

            Rectangle {
                visible: appController.latestPublicKey.length > 0
                width: 300
                height: 180
                radius: 12
                color: "#ffffff"
                border.color: "#d9d9d9"

                ScrollView {
                    anchors.fill: parent
                    anchors.margins: 10
                    clip: true

                    TextArea {
                        readOnly: true
                        text: appController.latestPublicKey
                        wrapMode: TextArea.WrapAnywhere
                        font.family: Theme.fontFamily
                        font.pixelSize: 11
                        background: null
                    }
                }
            }
        }
    }
}
