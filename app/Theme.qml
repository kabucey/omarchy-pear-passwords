pragma Singleton
import QtQuick
import Quickshell
import qs.Commons
import qs.Commons as Commons

// Every colour, radius and font here now comes from Omarchy's own design tokens (the same
// qs.Commons that Omapager Pro and the shell use), read from [controls]/[colors] in the
// theme's shell.toml. This used to parse ghostty.conf and invent its own palette, which
// looked close on one theme and wrong on the next - the exact failure Omapager Pro's
// DeedButton calls out. Names are kept so shell.qml needs no wholesale rewrite.
// Color is always Commons.Color: QtQuick 6.12 has its own Color type, which wins over a bare
// Color from qs.Commons and leaves every colour here undefined (a black window).
Singleton {
    readonly property color bg:           Commons.Color.popups.background
    readonly property color fg:           Commons.Color.popups.text
    readonly property color dim:          Commons.Color.muted
    readonly property color faint:        Commons.Color.muted
    readonly property color accent:       Commons.Color.accent
    readonly property color danger:       Commons.Color.urgent
    // Rows: the same selected fill Omarchy's own menus use.
    readonly property color selected:     Commons.Color.menu.selectedBackground
    readonly property color selectedText: Commons.Color.menu.selectedText
    readonly property color hover:        Commons.Color.menu.selectedBackground
    readonly property color panel:        Commons.Color.menu.selectedBackground
    readonly property color line:         Qt.rgba(Commons.Color.foreground.r,
                                                  Commons.Color.foreground.g,
                                                  Commons.Color.foreground.b, 0.12)
    readonly property string uiFont:      Style.font.family
    // Omarchy's controls are square. Everything here was rounded 6-9px by hand.
    readonly property int radius:         Style.cornerRadius

    // Type. Omarchy's Style.font ramp (caption 10 / body 12 / heading 16) is sized for bar
    // flyouts and panel rows. This is an app window people read passwords in, so the whole
    // ramp is scaled up - but still multiplied off Style.font, so it keeps following the
    // [font] base-size in shell.toml rather than freezing at whatever looks right today.
    readonly property real appScale:  1.25
    readonly property int fCaption:   Math.round(Style.font.caption   * appScale)
    readonly property int fSmall:     Math.round(Style.font.bodySmall * appScale)
    readonly property int fBody:      Math.round(Style.font.body      * appScale)
    readonly property int fHeading:   Math.round(Style.font.heading   * appScale)
}
