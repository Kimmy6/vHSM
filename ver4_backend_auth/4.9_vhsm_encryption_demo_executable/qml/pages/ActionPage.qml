import QtQuick
import QtQuick.Controls
import "../components"
import "../styles" 1.0

Page {
    property var stackViewRef
    background: Rectangle { color: "#f7f7f7" }

    ScrollView {
        anchors.fill: parent
        contentWidth: parent.width

        Column {
            width: parent.width
            spacing: 0

            AppHeader {}

            Column {
                anchors.horizontalCenter: parent.horizontalCenter
                topPadding: 40
                spacing: 16
                width: 300

                Text {
                    text: "안녕하세요, " + (appController.currentUser.length > 0 ? appController.currentUser : "User") + " 님."
                    font.family: Theme.fontFamily
                    font.pixelSize: 18
                    font.bold: true
                    color: "#111111"
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                // ── 선택된 파일 표시 ──────────────────────────────────
                Rectangle {
                    width: 300
                    height: 44
                    radius: 8
                    color: "#f0f0f0"
                    border.color: "#dddddd"
                    border.width: 1
                    anchors.horizontalCenter: parent.horizontalCenter

                    Row {
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.margins: 12
                        spacing: 8

                        Text {
                            text: "📁"
                            font.pixelSize: 14
                        }
                        Text {
                            text: appController.selectedFile.length > 0
                                  ? appController.selectedFile.split("/").pop()
                                  : "선택된 파일 없음"
                            font.family: Theme.fontFamily
                            font.pixelSize: 12
                            color: appController.selectedFile.length > 0 ? "#333333" : "#aaaaaa"
                            elide: Text.ElideMiddle
                            width: 240
                        }
                    }
                }

                // ── 키 번호 입력 ──────────────────────────────────────
                Text {
                    text: "키 번호 (1 / 2 / 3)"
                    font.family: Theme.fontFamily
                    font.pixelSize: 12
                    color: "#555555"
                }
                AppTextField {
                    id: keyNumberField
                    width: 300
                    placeholderText: "1, 2, 3 중 입력"
                    inputMethodHints: Qt.ImhDigitsOnly
                    leftPadding: 14; rightPadding: 14
                    topPadding: 0; bottomPadding: 0
                    verticalAlignment: TextInput.AlignVCenter
                }

                // ── 암호화 / 복호화 버튼 ──────────────────────────────
                AppButton {
                    text: "암호화 하기"
                    width: 300
                    anchors.horizontalCenter: parent.horizontalCenter
                    enabled: appController.selectedFile.length > 0
                    opacity: enabled ? 1.0 : 0.4
                    onClicked: {
                        appController.startEncryptWithKey(keyNumberField.text)
                    }
                }

                AppButton {
                    text: "복호화 하기"
                    width: 300
                    anchors.horizontalCenter: parent.horizontalCenter
                    enabled: appController.selectedFile.length > 0
                    opacity: enabled ? 1.0 : 0.4
                    onClicked: {
                        appController.startDecryptWithKey(keyNumberField.text)
                    }
                }

                // ── 상태 메시지 ────────────────────────────────────────
                Text {
                    text: appController.statusMessage
                    visible: text.length > 0
                    color: appController.statusMessage.startsWith("데이터") ? "#1a7a3c" : "#cc2222"
                    font.family: Theme.fontFamily
                    font.pixelSize: 13
                    font.bold: appController.statusMessage.startsWith("데이터")
                    width: 300
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    anchors.horizontalCenter: parent.horizontalCenter
                }

                // ── 결과 영역 ──────────────────────────────────────────
                Column {
                    width: 300
                    spacing: 10
                    visible: appController.resultFilePath.length > 0
                    anchors.horizontalCenter: parent.horizontalCenter

                    Rectangle {
                        width: 300
                        height: 1
                        color: "#e0e0e0"
                    }

                    // 결과 파일 경로 박스
                    Rectangle {
                        width: 300
                        height: resultPathCol.implicitHeight + 20
                        radius: 8
                        color: "#f0faf4"
                        border.color: "#a8d5b5"
                        border.width: 1

                        Column {
                            id: resultPathCol
                            anchors { left: parent.left; right: parent.right; top: parent.top; margins: 12 }
                            spacing: 4

                            Text {
                                text: "💾 저장 위치"
                                font.family: Theme.fontFamily
                                font.pixelSize: 11
                                color: "#555555"
                            }
                            Text {
                                text: appController.resultFilePath
                                font.family: Theme.fontFamily
                                font.pixelSize: 11
                                color: "#1a7a3c"
                                width: 276
                                wrapMode: Text.WrapAnywhere
                            }
                        }
                    }

                    // 복호화된 경우 이미지 미리보기
                    Image {
                        id: resultPreview
                        width: 300
                        height: 180
                        fillMode: Image.PreserveAspectFit
                        source: {
                            var p = appController.resultFilePath
                            if (p.length > 0 && !p.endsWith(".enc"))
                                return "file://" + p
                            return ""
                        }
                        visible: source.toString().length > 0
                    }

                    // 갤러리에서 확인 안내 (암호화된 .enc 파일)
                    Text {
                        visible: appController.resultFilePath.endsWith(".enc")
                        text: "갤러리 앱에서 확인하거나\n파일 관리자에서 위 경로를 열어보세요."
                        font.family: Theme.fontFamily
                        font.pixelSize: 11
                        color: "#666666"
                        horizontalAlignment: Text.AlignHCenter
                        width: 300
                        wrapMode: Text.WordWrap
                        anchors.horizontalCenter: parent.horizontalCenter
                    }
                }

                Item { height: 30 }
            }
        }
    }
}
