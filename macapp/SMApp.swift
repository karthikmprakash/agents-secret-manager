// sm — native macOS shell for the local sm UI.
//
// The app starts the bundled `sm ui --no-open` binary, reads the loopback URL
// (with its session token) from stdout, and shows it in a WKWebView. The child
// process is terminated when the app quits.
import Cocoa
import WebKit

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow!
    private var webView: WKWebView!
    private var server: Process?
    private var buffer = ""

    func applicationDidFinishLaunching(_ notification: Notification) {
        let rect = NSRect(x: 0, y: 0, width: 1040, height: 720)
        window = NSWindow(contentRect: rect,
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "sm — secrets for agents"
        window.minSize = NSSize(width: 760, height: 520)
        window.center()

        webView = WKWebView(frame: rect, configuration: WKWebViewConfiguration())
        window.contentView = webView
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)

        startServer()
    }

    private func startServer() {
        let macos = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS")
        let sm = macos.appendingPathComponent("sm").path

        let process = Process()
        process.executableURL = URL(fileURLWithPath: sm)
        process.arguments = ["ui", "--no-open"]
        process.currentDirectoryURL = FileManager.default.homeDirectoryForCurrentUser

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async { self?.handleOutput(text) }
        }

        do {
            try process.run()
            server = process
        } catch {
            showError("Could not start the sm service:\n\(error.localizedDescription)")
        }
    }

    private func handleOutput(_ text: String) {
        buffer += text
        guard webView.url == nil,
              let range = buffer.range(of: #"http://127\.0\.0\.1:[0-9]+/\?token=[a-f0-9]+"#,
                                       options: .regularExpression),
              let url = URL(string: String(buffer[range]))
        else { return }
        webView.load(URLRequest(url: url))
    }

    private func showError(_ text: String) {
        let escaped = text
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
        let html = """
        <html><body style="font: 14px -apple-system; padding: 40px;">
        <h2>sm could not start</h2><pre>\(escaped)</pre></body></html>
        """
        webView.loadHTMLString(html, baseURL: nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillTerminate(_ notification: Notification) {
        server?.terminate()
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.regular)

let mainMenu = NSMenu()

let appItem = NSMenuItem()
mainMenu.addItem(appItem)
let appMenu = NSMenu()
appMenu.addItem(withTitle: "About sm",
                action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
                keyEquivalent: "")
appMenu.addItem(.separator())
appMenu.addItem(withTitle: "Quit sm",
                action: #selector(NSApplication.terminate(_:)),
                keyEquivalent: "q")
appItem.submenu = appMenu

let editItem = NSMenuItem()
mainMenu.addItem(editItem)
let editMenu = NSMenu(title: "Edit")
editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
editMenu.addItem(.separator())
editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
editItem.submenu = editMenu

app.mainMenu = mainMenu

let delegate = AppDelegate()
app.delegate = delegate
app.run()
