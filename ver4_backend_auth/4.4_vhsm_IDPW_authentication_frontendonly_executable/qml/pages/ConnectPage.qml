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

            // Pi IP 토글 버튼
            Rectangle {
                width: 300
                height: 36
                radius: 8
                color: piIpExpanded ? "#f0f0f0" : "#ffffff"
                border.color: "#dddddd"
                border.width: 1
                anchors.horizontalCenter: parent.horizontalCenter

                property bool piIpExpanded: false

                Row {
                    anchors.centerIn: parent
                    spacing: 6

                    Text {
                        text: "Pi IP 설정"
                        font.family: Theme.fontFamily
                        font.pixelSize: 13
                        color: "#555555"
                        anchors.verticalCenter: parent.verticalCenter
                    }

                    Text {
                        text: parent.parent.piIpExpanded ? "▲" : "▼"
                        font.family: Theme.fontFamily
                        font.pixelSize: 11
                        color: "#888888"
                        anchors.verticalCenter: parent.verticalCenter
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                        parent.piIpExpanded = !parent.piIpExpanded
                        piHostField.visible = parent.piIpExpanded
                    }
                }
            }

            // Pi IP 입력 필드 — 토글에 따라 표시/숨김
            AppTextField {
                id: piHostField
                visible: false
                placeholderText: "Pi Tailscale IP 또는 MagicDNS"
                text: "100.114.157.74"
                leftPadding: 14; rightPadding: 14
                topPadding: 0; bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter

                // visible이 바뀔 때 부드럽게 나타나도록
                Behavior on opacity {
                    NumberAnimation { duration: 150 }
                }
                opacity: visible ? 1.0 : 0.0
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
