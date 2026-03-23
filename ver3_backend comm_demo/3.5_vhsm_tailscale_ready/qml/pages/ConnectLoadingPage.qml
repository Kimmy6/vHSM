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

        Item { Layout.fillHeight: true }

        ColumnLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: 12

            Text {
                text: "가상 HSM 접속 중..."
                font.family: Theme.fontFamily
                font.pixelSize: 20
                font.bold: true
                color: "#111111"
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
            }

            Text {
                text: "잠시만 기다려주세요..."
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#444444"
                horizontalAlignment: Text.AlignHCenter
                Layout.alignment: Qt.AlignHCenter
            }

            Item { implicitHeight: 18 }

            LoadingSpinner { Layout.alignment: Qt.AlignHCenter }
        }

        Item { Layout.fillHeight: true }

        Rectangle {
            Layout.fillWidth: true
            height: 1
            color: "#e6e6e6"
        }
    }
}
