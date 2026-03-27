import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import "../components"
import "../styles" 1.0

Page {
    property var stackViewRef
    background: Rectangle { color: "#f7f7f7" }

    // 갤러리(파일) 선택 다이얼로그
    FileDialog {
        id: fileDialog
        title: "이미지 선택"
        nameFilters: ["이미지 파일 (*.jpg *.jpeg *.png *.bmp *.gif)", "암호화 파일 (*.enc)", "모든 파일 (*)"]
        onAccepted: {
            // "file://" 제거 후 경로 저장
            var path = selectedFile.toString().replace("file://", "")
            appController.selectFile(path)
            previewImage.source = selectedFile
            selectedFileName.text = path.split("/").pop()
        }
    }

    Column {
        anchors.fill: parent
        spacing: 0

        AppHeader {}

        Column {
            anchors.horizontalCenter: parent.horizontalCenter
            topPadding: 56
            spacing: 20
            width: 300

            Text {
                text: "안녕하세요, " + (appController.currentUser.length > 0 ? appController.currentUser : "User") + " 님."
                font.family: Theme.fontFamily
                font.pixelSize: 18
                font.bold: true
                color: "#111111"
                anchors.horizontalCenter: parent.horizontalCenter
            }

            // ── 이미지 미리보기 영역 ───────────────────────────────────
            Rectangle {
                width: 300
                height: 200
                radius: 10
                color: "#eeeeee"
                border.color: "#cccccc"
                border.width: 1
                anchors.horizontalCenter: parent.horizontalCenter
                clip: true

                Image {
                    id: previewImage
                    anchors.fill: parent
                    fillMode: Image.PreserveAspectFit
                    visible: source.toString().length > 0
                }

                Text {
                    anchors.centerIn: parent
                    text: "선택된 파일 없음"
                    font.family: Theme.fontFamily
                    font.pixelSize: 13
                    color: "#999999"
                    visible: previewImage.source.toString().length === 0
                }
            }

            // 선택된 파일명 표시
            Text {
                id: selectedFileName
                text: appController.selectedFile.length > 0
                      ? appController.selectedFile.split("/").pop()
                      : ""
                visible: text.length > 0
                font.family: Theme.fontFamily
                font.pixelSize: 11
                color: "#666666"
                width: 300
                wrapMode: Text.WrapAnywhere
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }

            // ── 데이터 불러오기 버튼 ──────────────────────────────────
            AppButton {
                text: "데이터 불러오기"
                width: 300
                anchors.horizontalCenter: parent.horizontalCenter
                onClicked: fileDialog.open()
            }

            // ── 암호화/복호화 페이지로 이동 ───────────────────────────
            AppButton {
                text: "암호화 / 복호화 하기"
                width: 300
                anchors.horizontalCenter: parent.horizontalCenter
                enabled: appController.selectedFile.length > 0
                opacity: enabled ? 1.0 : 0.4
                onClicked: {
                    stackViewRef.push(Qt.resolvedUrl("ActionPage.qml"),
                                      { "stackViewRef": stackViewRef })
                }
            }

            // ── 로그아웃 ──────────────────────────────────────────────
            Text {
                text: "가상HSM 로그아웃"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#888888"
                anchors.horizontalCenter: parent.horizontalCenter
                MouseArea {
                    anchors.fill: parent
                    onClicked: appController.goBackToConnectPage()
                }
            }
        }
    }
}
