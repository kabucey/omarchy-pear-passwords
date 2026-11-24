import QtQuick

// Touchpad momentum for one Flickable, done the way GTK 4 does it (gtkeventcontrollerscroll.c,
// gtkkineticscrolling.c): while fingers move, the content follows them pixel for pixel; when they
// lift, the speed of the last 150 ms carries on and decays as v(t) = v0 * e^(-4t).
//
// Why the app does this at all: on Wayland nobody else will. libinput leaves momentum to the
// toolkit on purpose, Hyprland has no such option, and Qt Quick only does it on macOS, where the
// system sends momentum events. GTK 4, Firefox and Chromium each add it themselves from the
// same signal used here: a touchpad gesture's wl_pointer.axis_stop, which Qt hands over as a
// wheel event in phase ScrollEnd.
//
// Only touchpad gestures (a ScrollBegin, then pixel deltas) are taken. A mouse wheel has no
// phases and no end, so its events are left to the Flickable underneath exactly as before, and
// so are presses, drags, hover and the scroll bar: this item declines every press.
//
// Usage: declare it inside a Flickable or ListView as `KineticScroll { flickable: <id> }`. It
// moves itself out of the content onto the Flickable, above the content, at the same size.
MouseArea {
    id: k
    required property Flickable flickable

    // GTK 4's constants, so a flick here travels like one in a GTK app beside it.
    readonly property real friction: 4        // DECELERATION_FRICTION, per second
    readonly property int captureMs: 150      // SCROLL_CAPTURE_THRESHOLD_MS
    readonly property real minFlick: 50       // px/s: slower than this when the fingers lift is a stop
    readonly property real stopBelow: 10      // px/s: the glide ends (GTK's last pixels are invisible)

    parent: flickable
    anchors.fill: parent
    z: 1000
    acceptedButtons: Qt.AllButtons            // only to see a press; every press is declined
    hoverEnabled: false

    readonly property bool gliding: glide.running
    property bool gesture: false              // inside a touchpad gesture (saw its ScrollBegin)
    property var samples: []                  // [{t, dx, dy}] of the current gesture
    property real vx: 0
    property real vy: 0
    property real lastX: 0
    property real lastY: 0

    function minX() { return flickable.originX - flickable.leftMargin; }
    function maxX() { return Math.max(minX(), flickable.originX + flickable.contentWidth
                                              + flickable.rightMargin - flickable.width); }
    function minY() { return flickable.originY - flickable.topMargin; }
    function maxY() { return Math.max(minY(), flickable.originY + flickable.contentHeight
                                              + flickable.bottomMargin - flickable.height); }
    function canX() { return flickable.flickableDirection !== Flickable.VerticalFlick && maxX() > minX() + 0.5; }
    function canY() { return flickable.flickableDirection !== Flickable.HorizontalFlick && maxY() > minY() + 0.5; }
    function clamp(v, lo, hi) { return Math.min(hi, Math.max(lo, v)); }

    function stop() {
        if (!glide.running) return;
        glide.stop();
        // Rest on whole pixels, so text is not left blurred between two.
        if (canY()) flickable.contentY = Math.round(flickable.contentY);
        if (canX()) flickable.contentX = Math.round(flickable.contentX);
    }

    // Move by a touchpad delta, in Qt's sign (the same one Flickable uses: content -= delta).
    function moveBy(dx, dy) {
        if (canX() && dx) flickable.contentX = clamp(flickable.contentX - dx, minX(), maxX());
        if (canY() && dy) flickable.contentY = clamp(flickable.contentY - dy, minY(), maxY());
        lastX = flickable.contentX;
        lastY = flickable.contentY;
    }

    // One touchpad event. Returns whether it was taken. `t` is in ms. Split out of onWheel so a
    // test can drive a gesture without a touchpad.
    function feed(phase, dx, dy, t) {
        if (phase === Qt.ScrollBegin) {
            stop();
            flickable.cancelFlick();
            gesture = true;
            samples = [];
        } else if (!gesture || (phase !== Qt.ScrollUpdate && phase !== Qt.ScrollEnd)) {
            return false;                                 // a mouse wheel: Qt's own handling
        }
        if (!canX() && !canY()) {
            if (phase === Qt.ScrollEnd) gesture = false;
            return false;                                 // nothing to scroll here: let it through
        }
        if (dx || dy) {
            stop();
            moveBy(dx, dy);
            const s = samples.filter(function (p) { return p.t >= t - captureMs; });
            s.push({ t: t, dx: dx, dy: dy });
            samples = s;
        }
        if (phase === Qt.ScrollEnd) {
            gesture = false;
            const recent = samples.filter(function (p) { return p.t >= t - captureMs; });
            samples = [];
            if (recent.length < 2) return true;           // a nudge, or fingers that paused first
            const span = Math.max(8, t - recent[0].t) / 1000;
            let sx = 0, sy = 0;
            recent.forEach(function (p) { sx += p.dx; sy += p.dy; });
            vx = canX() ? -sx / span : 0;
            vy = canY() ? -sy / span : 0;
            if (Math.hypot(vx, vy) >= minFlick) {
                lastX = flickable.contentX;
                lastY = flickable.contentY;
                glide.start();
            }
        }
        return true;
    }

    onWheel: function (w) {
        w.accepted = k.feed(w.phase, w.pixelDelta.x, w.pixelDelta.y, Date.now());
    }

    // Any press in the area stops a glide, as it does in GTK. The press itself is declined, so
    // it still goes on to the row, the text or the scroll bar underneath.
    onPressed: function (m) { k.stop(); m.accepted = false; }
    onVisibleChanged: if (!visible) stop()

    FrameAnimation {
        id: glide
        onTriggered: {
            const f = k.flickable;
            // Someone else moved it (keys, the scroll bar, a jump to a row): theirs wins.
            if (Math.abs(f.contentX - k.lastX) > 1 || Math.abs(f.contentY - k.lastY) > 1) {
                k.stop();
                return;
            }
            const dt = Math.min(0.05, frameTime);
            const decay = Math.exp(-k.friction * dt);
            const step = (1 - decay) / k.friction;        // exact integral of v over dt
            const nx = k.clamp(f.contentX + k.vx * step, k.minX(), k.maxX());
            const ny = k.clamp(f.contentY + k.vy * step, k.minY(), k.maxY());
            if (k.vx) f.contentX = nx;
            if (k.vy) f.contentY = ny;
            k.lastX = f.contentX;
            k.lastY = f.contentY;
            k.vx = (nx <= k.minX() || nx >= k.maxX()) ? 0 : k.vx * decay;
            k.vy = (ny <= k.minY() || ny >= k.maxY()) ? 0 : k.vy * decay;
            if (Math.hypot(k.vx, k.vy) < k.stopBelow) k.stop();
        }
    }
}
