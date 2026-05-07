import QtQuick
import "../styles" 1.0

Rectangle {
    id: root
    property bool showBackButton: false
    signal backClicked()

    width: parent ? parent.width : 390
    height: 84
    color: "#f7f7f7"
    border.width: 1
    border.color: "#ebebeb"

    Item {
        visible: root.showBackButton
        width: 40
        height: 40
        anchors.left: parent.left
        anchors.leftMargin: 12
        anchors.verticalCenter: parent.verticalCenter

        Text {
            anchors.centerIn: parent
            text: "←"
            font.family: Theme.fontFamily
            font.pixelSize: 24
            color: "#111111"
        }

        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: root.backClicked()
        }
    }

    Text {
        anchors.left: parent.left
        anchors.leftMargin: root.showBackButton ? 52 : 24
        anchors.verticalCenter: parent.verticalCenter
        text: "PNU virtual HSM"
        font.family: Theme.fontFamily
        font.pixelSize: 22
        font.bold: true
        color: "#111111"
    }
}
