// protonmcp-touchid — Touch ID + NSAlert helper for proto-mcp.
//
// Spec:
//   - Read one JSON object from stdin (single line or multi-line).
//   - If confirm: true, show an NSAlert whose body is the full
//     operation text in a scroll view. macOS puts LAContext's
//     localizedReason in the dialog title and clips it, so a send's
//     recipient list cannot live only there (issue #125). Cancel
//     exits 1 and skips biometrics.
//   - Then run LAContext.evaluatePolicy(.deviceOwnerAuthentication).
//     When the alert already showed the body, the Touch ID reason is
//     the short title. Otherwise the reason is the body, as before.
//   - Exit 0 on biometric/password success, 1 on deny/cancel/
//     auth-fail, 2 on stdin parse error.
//
// Distribution: ad-hoc signed by swiftc on the dev machine. Phase 7
// adds Developer ID signing + notarization + NSFaceIDUsageDescription
// in an Info.plist when we bundle this as a .app.

import AppKit
import Foundation
import LocalAuthentication

struct Request: Codable {
    let title: String
    let body: String
    let caller: String?
    let confirm: Bool?
}

let data = FileHandle.standardInput.readDataToEndOfFile()
guard let req = try? JSONDecoder().decode(Request.self, from: data) else {
    FileHandle.standardError.write(Data("malformed stdin\n".utf8))
    exit(2)
}

// AppKit needs an NSApplication for NSAlert. Without this the alert
// silently no-ops. .accessory keeps a one-shot prompt out of the Dock.
let app = NSApplication.shared
app.setActivationPolicy(.accessory)

// confirm: true is the policy flag for "show the literal operation
// before Touch ID" (mail_send and the other irreversible tools).
// The body goes in a scroll view, not informativeText: informative
// text is clipped, and a clipped BCC line is the bug #125 closed.
if req.confirm == true {
    var full = req.body
    if let caller = req.caller, !caller.isEmpty {
        if !full.isEmpty {
            full += "\n\n"
        }
        full += "Requested by: \(caller)"
    }

    let alert = NSAlert()
    alert.messageText = req.title.isEmpty ? "Approve this action?" : req.title
    alert.alertStyle = .warning
    alert.addButton(withTitle: "Allow")
    alert.addButton(withTitle: "Cancel")
    let allowButton = alert.buttons[0]
    alert.accessoryView = scrollableBody(full, allow: allowButton)

    NSApp.activate(ignoringOtherApps: true)
    if alert.runModal() != .alertFirstButtonReturn {
        exit(1)
    }
}

// D30 (Phase 7/A): use .deviceOwnerAuthentication instead of
// .deviceOwnerAuthenticationWithBiometrics so the system falls back
// to the user's login password when biometric hardware is missing
// or disabled (Mac Mini, a Mac with a broken Touch ID sensor, Screen
// Sharing). Without this fallback, every prompted tool was simply
// inoperable on those Macs. Touch ID still runs FIRST on hardware
// that has it.
let ctx = LAContext()
var laError: NSError?
guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &laError) else {
    FileHandle.standardError.write(Data("authentication not available: \(laError?.localizedDescription ?? "unknown")\n".utf8))
    exit(1)
}

// The Touch ID sheet's localizedReason is a title on macOS, not a
// scrolling body. After the alert has shown every recipient, the
// reason stays the short title so the sheet cannot clip the list
// the user just approved.
var reason: String
if req.confirm == true {
    reason = req.title.isEmpty ? "Approve this action" : req.title
} else {
    reason = req.body
    if let caller = req.caller, !caller.isEmpty {
        reason += "\n\nRequested by: \(caller)"
    }
}

let sem = DispatchSemaphore(value: 0)
var ok = false
ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, evalErr in
    ok = success
    if !success, let e = evalErr {
        FileHandle.standardError.write(Data("evaluatePolicy: \(e.localizedDescription)\n".utf8))
    }
    sem.signal()
}
sem.wait()
exit(ok ? 0 : 1)

// scrollableBody lays the approval text out at its real height and
// shows as much of that as fits. A list that is taller than the
// viewport starts with Allow disabled; scrolling to the end enables
// it, so a Bcc past the first screen cannot be approved unseen.
// The Go side labels each list "To (n)", "Cc (n)", and "Bcc (n)".
func scrollableBody(_ text: String, allow: NSButton) -> NSScrollView {
    let width: CGFloat = 480
    let view = NSTextView(frame: NSRect(x: 0, y: 0, width: width - 16, height: 10))
    view.isEditable = false
    view.isSelectable = true
    view.isRichText = false
    view.font = NSFont.userFixedPitchFont(ofSize: 12)
    view.drawsBackground = false
    view.isVerticallyResizable = true
    view.isHorizontallyResizable = false
    view.textContainerInset = NSSize(width: 4, height: 6)
    view.minSize = NSSize(width: 0, height: 0)
    view.maxSize = NSSize(width: width - 16, height: CGFloat.greatestFiniteMagnitude)
    view.textContainer?.widthTracksTextView = true
    view.textContainer?.containerSize = NSSize(width: width - 16, height: CGFloat.greatestFiniteMagnitude)
    view.string = text
    view.layoutManager?.ensureLayout(for: view.textContainer!)
    let used = view.layoutManager?.usedRect(for: view.textContainer!) ?? .zero
    let contentH = max(used.height + view.textContainerInset.height * 2 + 8, 48)
    view.frame = NSRect(x: 0, y: 0, width: width - 16, height: contentH)

    // Cap the viewport well above a single line. 96pt hid every
    // recipient after the first wrapped To line, including Bcc.
    let maxH: CGFloat = 440
    let viewH = min(maxH, contentH)
    let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: width, height: viewH))
    scroll.hasVerticalScroller = true
    scroll.autohidesScrollers = contentH <= viewH + 1
    scroll.borderType = .bezelBorder
    scroll.drawsBackground = false
    scroll.documentView = view

    if contentH > viewH + 1 {
        allow.isEnabled = false
        scroll.contentView.postsBoundsChangedNotifications = true
        NotificationCenter.default.addObserver(
            forName: NSView.boundsDidChangeNotification,
            object: scroll.contentView,
            queue: .main
        ) { _ in
            let visible = scroll.contentView.bounds
            if visible.maxY >= view.bounds.maxY - 8 {
                allow.isEnabled = true
            }
        }
    }
    return scroll
}
