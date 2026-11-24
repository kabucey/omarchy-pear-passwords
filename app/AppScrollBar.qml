import QtQuick
import QtQuick.Controls

// Looks only: every scroll in the window is Qt's own Flickable, and this changes nothing about
// how it moves. The stock handle is a dark grey on a dark background (effectively invisible),
// so this one is the theme's text colour at 50% (clears the 3:1 non-text contrast minimum),
// shown while the position changes, wider and stronger under the pointer.
ScrollBar {
    id: bar
    property bool awake: false
    minimumSize: 0.06
    padding: 3

    onPositionChanged: { bar.awake = true; sleep.restart(); }
    Timer { id: sleep; interval: 900; onTriggered: bar.awake = false }

    contentItem: Rectangle {
        implicitWidth: bar.hovered || bar.pressed ? 9 : 6
        radius: width / 2
        color: Theme.fg
        opacity: bar.pressed ? 0.8 : bar.hovered ? 0.65 : bar.awake ? 0.5 : 0.0
        Behavior on opacity { NumberAnimation { duration: 200 } }
        Behavior on implicitWidth { NumberAnimation { duration: 120 } }
    }
    background: Item {}
}
