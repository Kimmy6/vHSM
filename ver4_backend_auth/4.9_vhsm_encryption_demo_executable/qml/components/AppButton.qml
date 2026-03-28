import QtQuick
import QtQuick.Controls
import "../styles" 1.0

Button {
    id: control
    property color bgColor: "#000000"
    property color fgColor: "#ffffff"
    implicitWidth: 300
    implicitHeight: 48

    background: Rectangle {
        radius: 8
        color: control.enabled ? control.bgColor : "#888888"
    }

    contentItem: Text {
        text: control.text
        color: control.fgColor
        font.family: Theme.fontFamily
        font.pixelSize: 15
        font.bold: true
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
    }
}
