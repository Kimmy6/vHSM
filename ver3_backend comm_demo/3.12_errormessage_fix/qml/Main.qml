import QtQuick
import QtQuick.Controls
import QtQml
import "pages"
import "styles" 1.0

ApplicationWindow {
    id: window
    width: 390
    height: 844
    visible: true
    title: "PNU Virtual HSM"
    color: "#f7f7f7"
    font.family: Theme.fontFamily

    StackView {
        id: stackView
        anchors.fill: parent
        initialItem: ConnectPage { stackViewRef: stackView }
    }

    Connections {
        target: appController

        function onOpenConnectLoadingPage() {
            stackView.push(Qt.resolvedUrl("pages/ConnectLoadingPage.qml"), { "stackViewRef": stackView })
        }

        function onConnectSuccess() {
            stackView.clear()
            stackView.push(Qt.resolvedUrl("pages/UploadPage.qml"), { "stackViewRef": stackView })
        }

        function onOpenRegeneratePage() {
            stackView.push(Qt.resolvedUrl("pages/RegenerateKeyPage.qml"), { "stackViewRef": stackView })
        }

        function onBackToConnectPage() {
            stackView.clear()
            stackView.push(Qt.resolvedUrl("pages/ConnectPage.qml"), { "stackViewRef": stackView })
        }

        function onOpenActionPage() {
            stackView.push(Qt.resolvedUrl("pages/ActionPage.qml"), { "stackViewRef": stackView })
        }

        function onOpenWorkLoadingPage() {
            stackView.push(Qt.resolvedUrl("pages/WorkLoadingPage.qml"), { "stackViewRef": stackView })
        }

        function onOperationFinished() {
            while (stackView.depth > 2)
                stackView.pop()
        }
    }
}
