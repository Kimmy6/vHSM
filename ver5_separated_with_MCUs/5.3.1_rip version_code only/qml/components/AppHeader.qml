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

    // ── 우측 상단 역할 배지 ──────────────────────────────────────────────────
    Rectangle {
        visible: appController.currentRole.length > 0
        anchors.right: parent.right
        anchors.rightMargin: 16
        anchors.verticalCenter: parent.verticalCenter
        height: 30
        width: roleLabel.implicitWidth + 20
        radius: 15
        color: {
            var r = appController.currentRole
            if (r === "hsm_root_officer")           return "#c0392b"
            if (r === "puf_maintenance_officer")     return "#8e44ad"
            if (r === "partition_security_officer")  return "#2980b9"
            if (r === "audit_user")                  return "#27ae60"
            return "#7f8c8d"   // public_user
        }

        Text {
            id: roleLabel
            anchors.centerIn: parent
            font.family: Theme.fontFamily
            font.pixelSize: 11
            font.bold: true
            color: "white"
            text: {
                var r = appController.currentRole
                if (r === "hsm_root_officer")           return "Root Officer"
                if (r === "puf_maintenance_officer")     return "PUF Maintenance"
                if (r === "partition_security_officer")  return "Partition SO"
                if (r === "audit_user")                  return "Audit User"
                if (r === "public_user")                 return "Public User"
                return ""
            }
        }
    }
}
