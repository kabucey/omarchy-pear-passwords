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

    // How far content moves per touchpad pixel. Qt applies Hyprland's touchpad scroll_factor
    // (0.4 on Omarchy, often lower) to the deltas as they are, so at 1 the content crawls well
    // behind the fingers. The glide follows, since its speed is measured from these moves.
    readonly property real speed: 3
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
    // [{t, dx, dy}] of the gesture's last captureMs, trimmed from the front and changed in
    // place: one small array per gesture, not one per event.
    property var samples: []
    property real vx: 0
    property real vy: 0
    property real lastX: 0
    property real lastY: 0

    // The scrollable range, read once per event or frame. can* is false for an axis that has
    // nowhere to go or that the Flickable does not scroll.
    function bounds() {
        const f = flickable;
        const x0 = f.originX - f.leftMargin, y0 = f.originY - f.topMargin;
        const x1 = Math.max(x0, f.originX + f.contentWidth + f.rightMargin - f.width);
        const y1 = Math.max(y0, f.originY + f.contentHeight + f.bottomMargin - f.height);
        return { x0: x0, x1: x1, y0: y0, y1: y1,
                 canX: f.flickableDirection !== Flickable.VerticalFlick && x1 > x0 + 0.5,
                 canY: f.flickableDirection !== Flickable.HorizontalFlick && y1 > y0 + 0.5 };
    }
    function clamp(v, lo, hi) { return Math.min(hi, Math.max(lo, v)); }
    function trim(t) { while (samples.length && samples[0].t < t - captureMs) samples.shift(); }

    function stop() {
        if (!glide.running) return;
        glide.stop();
        // Rest on whole pixels, so text is not left blurred between two.
        flickable.contentX = Math.round(flickable.contentX);
        flickable.contentY = Math.round(flickable.contentY);
    }

    // One touchpad event. Returns whether it was taken. `t` is in ms. Split out of onWheel so a
    // test can drive a gesture without a touchpad.
    function feed(phase, dx, dy, t) {
        if (phase === Qt.ScrollBegin) {
            stop();
            flickable.cancelFlick();
            gesture = true;
            samples.length = 0;
        } else if (!gesture || (phase !== Qt.ScrollUpdate && phase !== Qt.ScrollEnd)) {
            return false;                                 // a mouse wheel: Qt's own handling
        }
        const b = bounds();
        if (!b.canX && !b.canY) {
            if (phase === Qt.ScrollEnd) gesture = false;
            return false;                                 // nothing to scroll here: let it through
        }
        dx *= speed;
        dy *= speed;
        trim(t);
        if (dx || dy) {
            stop();
            // Qt's sign, the one Flickable uses: content -= delta.
            if (b.canX && dx) flickable.contentX = clamp(flickable.contentX - dx, b.x0, b.x1);
            if (b.canY && dy) flickable.contentY = clamp(flickable.contentY - dy, b.y0, b.y1);
            samples.push({ t: t, dx: dx, dy: dy });
        }
        if (phase === Qt.ScrollEnd) {
            gesture = false;
            const n = samples.length;
            if (n < 2) { samples.length = 0; return true; }   // a nudge, or fingers that paused first
            const span = Math.max(8, t - samples[0].t) / 1000;
            let sx = 0, sy = 0;
            for (let i = 0; i < n; ++i) { sx += samples[i].dx; sy += samples[i].dy; }
            samples.length = 0;
            vx = b.canX ? -sx / span : 0;
            vy = b.canY ? -sy / span : 0;
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
            const b = k.bounds();
            const nx = k.clamp(f.contentX + k.vx * step, b.x0, b.x1);
            const ny = k.clamp(f.contentY + k.vy * step, b.y0, b.y1);
            if (k.vx) f.contentX = nx;
            if (k.vy) f.contentY = ny;
            k.lastX = f.contentX;
            k.lastY = f.contentY;
            k.vx = (nx <= b.x0 || nx >= b.x1) ? 0 : k.vx * decay;
            k.vy = (ny <= b.y0 || ny >= b.y1) ? 0 : k.vy * decay;
            if (Math.hypot(k.vx, k.vy) < k.stopBelow) k.stop();
        }
    }
}
