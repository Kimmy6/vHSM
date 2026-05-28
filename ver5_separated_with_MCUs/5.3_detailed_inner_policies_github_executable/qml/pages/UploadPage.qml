import QtQuick
import QtQuick.Controls
import "../components"
import "../styles" 1.0

Page {
    property var stackViewRef
    background: Rectangle { color: "#f7f7f7" }

    Column {
        anchors.fill: parent
        spacing: 0
        AppHeader {}

        Column {
            anchors.horizontalCenter: parent.horizontalCenter
            topPadding: 80
            spacing: 18

            Text {
                text: "안녕하세요, " + appController.currentUser + "님."
                font.family: Theme.fontFamily
                font.pixelSize: 20
                font.bold: true
                color: "#111111"
            }

            AppTextField {
                id: filePathField
                placeholderText: "파일 경로 입력"
                text: appController.selectedFile
                onTextChanged: appController.selectFile(text)
                leftPadding: 14
                rightPadding: 14
                topPadding: 0
                bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            AppButton {
                text: "데이터 업로드하기"
                onClicked: appController.uploadData()
            }

            Text {
                text: appController.statusMessage
                visible: text.length > 0
                color: appController.statusMessage.indexOf("complete") >= 0 ? "green" : "red"
                font.family: Theme.fontFamily
                font.pixelSize: 12
            }
        }
    }
}
