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

        AppHeader {
            showBackButton: true
            onBackClicked: appController.goBackToConnectPage()
        }

        Column {
            anchors.horizontalCenter: parent.horizontalCenter
            topPadding: 72
            spacing: 16

            Text {
                text: "패스워드 찾기"
                font.family: Theme.fontFamily
                font.pixelSize: 22
                font.bold: true
                color: "#111111"
                anchors.horizontalCenter: parent.horizontalCenter
                bottomPadding: 16
            }

            Text {
                text: "이름"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#333333"
                leftPadding: 4
            }

            AppTextField {
                id: findPwNameField
                placeholderText: ""
                leftPadding: 14; rightPadding: 14
                topPadding: 0; bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            Item { width: 1; height: 4 }

            Text {
                text: "아이디"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                color: "#333333"
                leftPadding: 4
            }

            AppTextField {
                id: findPwIdField
                placeholderText: ""
                leftPadding: 14; rightPadding: 14
                topPadding: 0; bottomPadding: 0
                verticalAlignment: TextInput.AlignVCenter
            }

            Item { width: 1; height: 8 }

            AppButton {
                text: "계정 확인하기"
                onClicked: appController.findPassword(findPwNameField.text, findPwIdField.text)
            }

            Text {
                text: appController.findPasswordStatusMessage
                visible: text.length > 0
                color: text.indexOf("확인") >= 0 || text.indexOf("완료") >= 0 ? "#111111" : "red"
                font.family: Theme.fontFamily
                font.pixelSize: 13
                width: 300
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenter: parent.horizontalCenter
            }
        }
    }
}
