import QtQuick
import QtQuick.Controls
import "../styles" 1.0

TextField {
    implicitWidth: 300
    implicitHeight: 40
    leftPadding: 12
    font.family: Theme.fontFamily
    font.pixelSize: 14
    color: "#222222"
    placeholderTextColor: "#9b9b9b"

    background: Rectangle {
        radius: 8
        border.width: 1
        border.color: "#dddddd"
        color: "#ffffff"
    }
}
