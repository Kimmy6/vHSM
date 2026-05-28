import QtQuick
import QtQuick.Controls
import "../components"
import "../styles" 1.0

Page {
    property var stackViewRef
    background: Rectangle { color: "#f7f7f7" }

    Component.onCompleted: appController.requestAuditLog()

    Column {
        anchors.fill: parent
        spacing: 0

        AppHeader {}

        Column {
            width: parent.width
            topPadding: 24
            spacing: 16

            Text {
                text: "감사 로그"
                font.family: Theme.fontFamily
                font.pixelSize: 20
                font.bold: true
                color: "#111111"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            Text {
                text: "읽기 전용 — 키 관리 권한 없음"
                font.family: Theme.fontFamily
                font.pixelSize: 12
                color: "#888888"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            // ── 새로고침 버튼 ─────────────────────────────────────────
            AppButton {
                text: "새로고침"
                width: 160
                anchors.horizontalCenter: parent.horizontalCenter
                onClicked: appController.requestAuditLog()
            }

            // ── 로그 목록 ─────────────────────────────────────────────
            Rectangle {
                width: parent.width - 32
                height: 560
                radius: 10
                color: "#ffffff"
                border.color: "#e0e0e0"
                border.width: 1
                anchors.horizontalCenter: parent.horizontalCenter
                clip: true

                ListView {
                    id: logListView
                    anchors.fill: parent
                    anchors.margins: 8
                    spacing: 6
                    model: {
                        try {
                            var raw = JSON.parse(appController.auditLogJson)
                            // raw 는 JSON 문자열 배열 — 각 항목을 파싱
                            var parsed = []
                            for (var i = raw.length - 1; i >= 0; i--) {
                                try { parsed.push(JSON.parse(raw[i])) }
                                catch(e) { parsed.push({ event: raw[i] }) }
                            }
                            return parsed
                        } catch(e) { return [] }
                    }

                    delegate: Rectangle {
                        width: logListView.width
                        height: entryCol.implicitHeight + 16
                        radius: 6
                        color: {
                            var ev = modelData.event || ""
                            if (ev.indexOf("FAIL") >= 0 || ev.indexOf("DENY") >= 0) return "#fff0f0"
                            if (ev.indexOf("ZEROIZE") >= 0) return "#fff8e1"
                            return "#f5f5f5"
                        }
                        border.color: "#e0e0e0"
                        border.width: 1

                        Column {
                            id: entryCol
                            anchors { left: parent.left; right: parent.right; top: parent.top; margins: 10 }
                            spacing: 2

                            Row {
                                spacing: 8
                                Text {
                                    text: modelData.event || "-"
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 13
                                    font.bold: true
                                    color: {
                                        var ev = modelData.event || ""
                                        if (ev.indexOf("FAIL") >= 0 || ev.indexOf("DENY") >= 0) return "#c0392b"
                                        if (ev.indexOf("ZEROIZE") >= 0) return "#e67e22"
                                        return "#2c3e50"
                                    }
                                }
                                Text {
                                    text: modelData.user ? ("· " + modelData.user) : ""
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 13
                                    color: "#555555"
                                }
                                Text {
                                    text: modelData.role ? ("[" + modelData.role + "]") : ""
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 11
                                    color: "#888888"
                                }
                            }

                            Text {
                                text: modelData.detail || ""
                                font.family: Theme.fontFamily
                                font.pixelSize: 11
                                color: "#666666"
                                visible: (modelData.detail || "") !== ""
                                wrapMode: Text.Wrap
                                width: parent.width
                            }

                            Text {
                                text: modelData.timestamp || ""
                                font.family: Theme.fontFamily
                                font.pixelSize: 10
                                color: "#aaaaaa"
                            }
                        }
                    }

                    Text {
                        anchors.centerIn: parent
                        visible: logListView.count === 0
                        text: "로그 없음"
                        font.family: Theme.fontFamily
                        font.pixelSize: 14
                        color: "#aaaaaa"
                    }
                }
            }
        }
    }
}
