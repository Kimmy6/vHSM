import QtQuick
import QtQuick.Controls
import "../components"
import "../styles" 1.0

Page {
    property var stackViewRef
    background: Rectangle { color: "#f7f7f7" }

    property var slotModel: []

    function refreshSlots() {
        appController.requestSlotList()
    }

    Connections {
        target: appController
        function onSlotListJsonChanged() {
            try {
                slotModel = JSON.parse(appController.slotListJson)
            } catch(e) {
                slotModel = []
            }
        }
    }

    Component.onCompleted: refreshSlots()

    Column {
        anchors.fill: parent
        spacing: 0

        AppHeader {
            showBackButton: true
            onBackClicked: stackViewRef ? stackViewRef.pop() : appController.goBackToConnectPage()
        }

        ScrollView {
            width: parent.width
            height: parent.height - 84
            contentWidth: parent.width

            Column {
                anchors.horizontalCenter: parent.horizontalCenter
                topPadding: 32
                spacing: 24
                width: 300

                Text {
                    text: "HSM 관리"
                    font.family: Theme.fontFamily
                    font.pixelSize: 20
                    font.bold: true
                    color: "#111111"
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                // ── 슬롯 목록 ──────────────────────────────────────────────
                Rectangle {
                    width: 300
                    height: slotListSection.height + 32
                    radius: 10
                    color: "white"
                    border.color: "#dddddd"
                    border.width: 1

                    Column {
                        id: slotListSection
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.top: parent.top
                        anchors.margins: 16
                        spacing: 8

                        Row {
                            width: parent.width
                            spacing: 8
                            Text {
                                text: "슬롯 목록"
                                font.family: Theme.fontFamily
                                font.pixelSize: 15
                                font.bold: true
                                color: "#2980b9"
                                anchors.verticalCenter: parent.verticalCenter
                            }
                            Item { width: parent.width - 90 - 8 - 68; height: 1 }
                            Rectangle {
                                width: 68; height: 28; radius: 6
                                color: "#ecf0f1"
                                border.color: "#bdc3c7"; border.width: 1
                                anchors.verticalCenter: parent.verticalCenter
                                Text {
                                    anchors.centerIn: parent
                                    text: "새로고침"
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 11
                                    color: "#555"
                                }
                                MouseArea {
                                    anchors.fill: parent
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: refreshSlots()
                                }
                            }
                        }

                        Text {
                            visible: slotModel.length === 0
                            text: "생성된 슬롯이 없습니다."
                            font.family: Theme.fontFamily
                            font.pixelSize: 12
                            color: "#999999"
                        }

                        Repeater {
                            model: slotModel
                            delegate: Rectangle {
                                width: 268; height: 48
                                radius: 8
                                color: "#f8f9fa"
                                border.color: "#dee2e6"; border.width: 1
                                Column {
                                    anchors.verticalCenter: parent.verticalCenter
                                    anchors.left: parent.left
                                    anchors.leftMargin: 12
                                    spacing: 2
                                    Text {
                                        text: modelData.name
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 13; font.bold: true
                                        color: "#111111"
                                    }
                                    Text {
                                        text: modelData.id
                                        font.family: Theme.fontFamily
                                        font.pixelSize: 10
                                        color: "#888888"
                                    }
                                }
                            }
                        }
                    }
                }

                // ── 슬롯 생성 ──────────────────────────────────────────────
                Rectangle {
                    width: 300
                    height: slotSection.height + 32
                    radius: 10
                    color: "white"
                    border.color: "#dddddd"; border.width: 1

                    Column {
                        id: slotSection
                        anchors.left: parent.left; anchors.right: parent.right
                        anchors.top: parent.top; anchors.margins: 16
                        spacing: 10

                        Text {
                            text: "슬롯 생성"
                            font.family: Theme.fontFamily
                            font.pixelSize: 15; font.bold: true
                            color: "#27ae60"
                        }
                        Text { text: "슬롯 이름"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        AppTextField {
                            id: slotNameField
                            placeholderText: "예: 연구실 A"
                            leftPadding: 14; rightPadding: 14
                            topPadding: 0; bottomPadding: 0
                            verticalAlignment: TextInput.AlignVCenter
                        }
                        AppButton {
                            text: "슬롯 생성"
                            onClicked: {
                                appController.createSlot(slotNameField.text)
                                slotNameField.text = ""
                            }
                        }
                    }
                }

                // ── 초대 코드 생성 ────────────────────────────────────────
                Rectangle {
                    width: 300
                    height: inviteSection.height + 32
                    radius: 10
                    color: "white"
                    border.color: "#dddddd"; border.width: 1

                    Column {
                        id: inviteSection
                        anchors.left: parent.left; anchors.right: parent.right
                        anchors.top: parent.top; anchors.margins: 16
                        spacing: 10

                        Text {
                            text: "초대 코드 생성"
                            font.family: Theme.fontFamily
                            font.pixelSize: 15; font.bold: true
                            color: "#e67e22"
                        }

                        Text { text: "슬롯 선택"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        ComboBox {
                            id: inviteSlotCombo
                            width: 268
                            enabled: slotModel.length > 0
                            model: {
                                if (slotModel.length === 0) return ["슬롯 없음"]
                                return slotModel.map(function(s) { return s.name + "  (" + s.id + ")" })
                            }
                            font.family: Theme.fontFamily; font.pixelSize: 12
                            background: Rectangle {
                                color: inviteSlotCombo.enabled ? "white" : "#f0f0f0"
                                radius: 8; border.color: "#ccc"; border.width: 1
                            }
                            contentItem: Text {
                                leftPadding: 14; text: inviteSlotCombo.displayText
                                font: inviteSlotCombo.font
                                color: inviteSlotCombo.enabled ? "#111" : "#999"
                                verticalAlignment: Text.AlignVCenter; elide: Text.ElideRight
                            }
                        }

                        Text { text: "부여할 역할"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        ComboBox {
                            id: inviteRoleCombo
                            width: 268
                            model: ["Audit User", "Partition Security Officer",
                                    "PUF Maintenance Officer", "Public User"]
                            font.family: Theme.fontFamily; font.pixelSize: 13
                            background: Rectangle { color: "white"; radius: 8; border.color: "#ccc"; border.width: 1 }
                            contentItem: Text {
                                leftPadding: 14; text: inviteRoleCombo.displayText
                                font: inviteRoleCombo.font; color: "#111"
                                verticalAlignment: Text.AlignVCenter
                            }
                        }

                        Text { text: "유효 기간 (일)"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        AppTextField {
                            id: expireDaysField
                            placeholderText: "7"
                            text: "7"
                            inputMethodHints: Qt.ImhDigitsOnly
                            leftPadding: 14; rightPadding: 14
                            topPadding: 0; bottomPadding: 0
                            verticalAlignment: TextInput.AlignVCenter
                        }

                        AppButton {
                            text: "초대 코드 생성"
                            enabled: slotModel.length > 0
                            onClicked: {
                                var sid = slotModel[inviteSlotCombo.currentIndex].id
                                appController.generateInvite(
                                    sid,
                                    inviteRoleCombo.currentIndex,
                                    parseInt(expireDaysField.text) || 7
                                )
                            }
                        }

                        // 생성된 코드 표시
                        Rectangle {
                            visible: appController.inviteCode.length > 0
                            width: 268; height: 52
                            radius: 8
                            color: "#fff8e1"
                            border.color: "#f39c12"; border.width: 1

                            Column {
                                anchors.centerIn: parent
                                spacing: 2
                                Text {
                                    text: "생성된 초대 코드"
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 10; color: "#888"
                                    anchors.horizontalCenter: parent.horizontalCenter
                                }
                                Text {
                                    text: appController.inviteCode
                                    font.family: Theme.fontFamily
                                    font.pixelSize: 22; font.bold: true
                                    color: "#e67e22"
                                    letterSpacing: 4
                                    anchors.horizontalCenter: parent.horizontalCenter
                                }
                            }
                        }
                    }
                }

                // ── 유저 생성 ──────────────────────────────────────────────
                Rectangle {
                    width: 300
                    height: userSection.height + 32
                    radius: 10
                    color: "white"
                    border.color: "#dddddd"; border.width: 1

                    Column {
                        id: userSection
                        anchors.left: parent.left; anchors.right: parent.right
                        anchors.top: parent.top; anchors.margins: 16
                        spacing: 10

                        Text {
                            text: "유저 생성"
                            font.family: Theme.fontFamily
                            font.pixelSize: 15; font.bold: true
                            color: "#8e44ad"
                        }

                        Text { text: "슬롯 선택"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        ComboBox {
                            id: slotCombo
                            width: 268
                            enabled: slotModel.length > 0
                            model: {
                                if (slotModel.length === 0) return ["슬롯 없음 — 먼저 슬롯을 생성하세요"]
                                return slotModel.map(function(s) { return s.name + "  (" + s.id + ")" })
                            }
                            font.family: Theme.fontFamily; font.pixelSize: 12
                            background: Rectangle {
                                color: slotCombo.enabled ? "white" : "#f0f0f0"
                                radius: 8; border.color: "#ccc"; border.width: 1
                            }
                            contentItem: Text {
                                leftPadding: 14; text: slotCombo.displayText
                                font: slotCombo.font
                                color: slotCombo.enabled ? "#111" : "#999"
                                verticalAlignment: Text.AlignVCenter
                                elide: Text.ElideRight
                            }
                        }

                        Text { text: "새 아이디"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        AppTextField {
                            id: newUserIdField; leftPadding: 14; rightPadding: 14
                            topPadding: 0; bottomPadding: 0; verticalAlignment: TextInput.AlignVCenter
                        }

                        Text { text: "비밀번호"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        AppTextField {
                            id: newPwField; echoMode: TextInput.Password
                            leftPadding: 14; rightPadding: 14
                            topPadding: 0; bottomPadding: 0; verticalAlignment: TextInput.AlignVCenter
                        }

                        Text { text: "비밀번호 확인"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        AppTextField {
                            id: newPwConfirmField; echoMode: TextInput.Password
                            leftPadding: 14; rightPadding: 14
                            topPadding: 0; bottomPadding: 0; verticalAlignment: TextInput.AlignVCenter
                        }

                        Text { text: "이름"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        AppTextField {
                            id: newNameField; leftPadding: 14; rightPadding: 14
                            topPadding: 0; bottomPadding: 0; verticalAlignment: TextInput.AlignVCenter
                        }

                        Text { text: "이메일 (선택)"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        AppTextField {
                            id: newEmailField; placeholderText: "@"
                            leftPadding: 14; rightPadding: 14
                            topPadding: 0; bottomPadding: 0; verticalAlignment: TextInput.AlignVCenter
                        }

                        Text { text: "역할"; font.family: Theme.fontFamily; font.pixelSize: 13; color: "#333" }
                        ComboBox {
                            id: roleCombo; width: 268
                            model: ["Audit User", "Partition Security Officer",
                                    "PUF Maintenance Officer", "Public User"]
                            font.family: Theme.fontFamily; font.pixelSize: 13
                            background: Rectangle { color: "white"; radius: 8; border.color: "#ccc"; border.width: 1 }
                            contentItem: Text {
                                leftPadding: 14; text: roleCombo.displayText
                                font: roleCombo.font; color: "#111"
                                verticalAlignment: Text.AlignVCenter
                            }
                        }

                        AppButton {
                            text: "유저 생성"
                            enabled: slotModel.length > 0
                            onClicked: {
                                var sid = slotModel[slotCombo.currentIndex].id
                                appController.createUserInSlot(
                                    sid, newUserIdField.text,
                                    newPwField.text, newPwConfirmField.text,
                                    newNameField.text, newEmailField.text,
                                    roleCombo.currentIndex
                                )
                            }
                        }
                    }
                }

                Text {
                    text: appController.signUpStatusMessage
                    visible: text.length > 0
                    color: text.indexOf("생성") >= 0 || text.indexOf("완료") >= 0 ? "#27ae60" : "#c0392b"
                    font.family: Theme.fontFamily; font.pixelSize: 12
                    width: 300; wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                Item { width: 1; height: 20 }
            }
        }
    }
}
