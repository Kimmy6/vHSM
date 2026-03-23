import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"
import "../styles" 1.0

Page {
    property var stackViewRef
    background: Rectangle { color: "#f7f7f7" }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        AppHeader { Layout.fillWidth: true }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.margins: 28
            spacing: 18

            Text {
                text: "가상 HSM 접속 중..."
                font.family: Theme.fontFamily
                font.pixelSize: 20
                font.bold: true
                color: "#111111"
            }

            Text {
                text: appController.connectionPhase
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#555555"
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }

            LoadingSpinner { Layout.alignment: Qt.AlignHCenter }

            Rectangle {
                Layout.fillWidth: true
                radius: 14
                color: "white"
                border.color: "#d9d9d9"
                border.width: 1
                implicitHeight: infoColumn.implicitHeight + 28

                ColumnLayout {
                    id: infoColumn
                    anchors.fill: parent
                    anchors.margins: 14
                    spacing: 10

                    Text {
                        text: "이 앱은 Raspberry Pi에 접속 시작 명령만 전송합니다."
                        font.family: Theme.fontFamily
                        font.pixelSize: 13
                        color: "#222222"
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }

                    Text {
                        text: "실제 진행 로그는 Pi의 LXTerminal 창에 표시됩니다."
                        font.family: Theme.fontFamily
                        font.pixelSize: 13
                        color: "#222222"
                        wrapMode: Text.WordWrap
                        Layout.fillWidth: true
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        radius: 10
                        color: "#f5f5f5"
                        border.color: "#e6e6e6"
                        border.width: 1
                        implicitHeight: terminalText.implicitHeight + 20

                        Text {
                            id: terminalText
                            anchors.fill: parent
                            anchors.margins: 10
                            text: appController.terminalLog
                            color: "#444444"
                            font.family: "monospace"
                            font.pixelSize: 12
                            wrapMode: Text.Wrap
                        }
                    }
                }
            }
        }
    }
}
