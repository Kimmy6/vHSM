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
            topPadding: 72
            spacing: 16

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

            Item { width: 1; height: 8 }

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

            // Pi IP 필드 (접기 가능)
            Column {
                anchors.horizontalCenter: parent.horizontalCenter
                spacing: 6

                Row {
                    anchors.horizontalCenter: parent.horizontalCenter
                    spacing: 6

                    Text {
                        text: "Pi IP 설정"
                        font.family: Theme.fontFamily
                        font.pixelSize: 12
                        color: "#888888"
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    Text {
                        text: piHostArea.visible ? "▲" : "▼"
                        font.pixelSize: 10
                        color: "#888888"
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    MouseArea {
                        width: 80; height: 24
                        anchors.verticalCenter: parent.verticalCenter
                        onClicked: piHostArea.visible = !piHostArea.visible
                    }
                }

                Column {
                    id: piHostArea
                    visible: false
                    anchors.horizontalCenter: parent.horizontalCenter
                    spacing: 0

                    AppTextField {
                        id: piHostField
                        placeholderText: "Pi Tailscale IP 또는 MagicDNS"
                        text: "100.114.157.74"
                        leftPadding: 14; rightPadding: 14
                        topPadding: 0; bottomPadding: 0
                        verticalAlignment: TextInput.AlignVCenter
                    }
                }
            }

            AppButton {
                text: "가상HSM 접속하기"
                onClicked: appController.connectToHsm(idField.text, piHostField.text)
            }

            Text {
                text: appController.statusMessage
                visible: text.length > 0
                color: "red"
                font.family: Theme.fontFamily
                font.pixelSize: 12
                width: 300
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Item { width: 1; height: 20 }

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
                        onClicked: appController.goToSignUpPage()
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
                        onClicked: appController.goToFindIdPage()
                    }
                }
            }
        }
    }
}
