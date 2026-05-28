import QtQuick

Item {
    width: 64
    height: 64

    Repeater {
        model: 8
        Rectangle {
            width: 8
            height: 18
            radius: 4
            color: "#d4d4d4"
            anchors.centerIn: parent
            transform: [
                Translate { y: -22 },
                Rotation { angle: index * 45; origin.x: 4; origin.y: 22 }
            ]
            SequentialAnimation on opacity {
                loops: Animation.Infinite
                running: true
                PauseAnimation { duration: index * 120 }
                NumberAnimation { from: 0.2; to: 1.0; duration: 450 }
                NumberAnimation { from: 1.0; to: 0.2; duration: 450 }
            }
        }
    }
}
