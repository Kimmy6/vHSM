import QtQuick
import "../styles" 1.0

Rectangle {
    width: parent ? parent.width : 390
    height: 84
    color: "#f7f7f7"
    border.width: 1
    border.color: "#ebebeb"

    Text {
        anchors.left: parent.left
        anchors.leftMargin: 24
        anchors.verticalCenter: parent.verticalCenter
        text: "PNU virtual HSM"
        font.family: Theme.fontFamily
        font.pixelSize: 22
        font.bold: true
        color: "#111111"
    }
}
