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
                Layout.fillHeight: true
                radius: 14
                color: "#111111"
                border.color: "#2f2f2f"
                border.width: 1

                Flickable {
                    anchors.fill: parent
                    anchors.margins: 14
                    contentHeight: terminalText.paintedHeight
                    clip: true

                    Text {
                        id: terminalText
                        width: parent.width
                        text: appController.terminalLog.length > 0 ? appController.terminalLog : "Pi terminal is waiting for logs..."
                        color: "#d6ffd6"
                        font.family: "monospace"
                        font.pixelSize: 13
                        wrapMode: Text.Wrap
                    }
                }
            }
        }
    }
}
