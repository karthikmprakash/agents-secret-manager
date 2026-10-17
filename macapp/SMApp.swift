// sm — native macOS shell for the local sm UI.
//
// The app starts the bundled `sm ui --no-open` binary, reads the loopback URL
// (with its session token) from stdout, and shows it in a WKWebView. The child
// process is terminated when the app quits.
import Cocoa
import WebKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate {
  private var window: NSWindow!
  private var webView: WKWebView!
  private var server: Process?
  private var buffer = ""
  private var serviceURL: URL?

  func applicationDidFinishLaunching(_ notification: Notification) {
    let rect = NSRect(x: 0, y: 0, width: 1040, height: 720)
    window = NSWindow(
      contentRect: rect,
      styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered, defer: false)
    window.title = "sm — secrets for agents"
    window.minSize = NSSize(width: 760, height: 520)
    window.center()

    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()
    webView = WKWebView(frame: rect, configuration: configuration)
    webView.navigationDelegate = self
    webView.uiDelegate = self
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
    process.standardError = FileHandle.nullDevice
    pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
      let data = handle.availableData
      guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
      Task { @MainActor [weak self] in self?.handleOutput(text) }
    }
    process.terminationHandler = { [weak self] process in
      guard process.terminationStatus != 0 else { return }
      Task { @MainActor [weak self] in
        self?.showError("The local service stopped. Quit and reopen sm.")
      }
    }

    do {
      try process.run()
      server = process
    } catch {
      showError("Could not start the sm service:\n\(error.localizedDescription)")
    }
  }

  private func handleOutput(_ text: String) {
    guard serviceURL == nil else { return }
    buffer += text
    if buffer.count > 4096 {
      buffer = ""
      showError("The local service returned an invalid startup response.")
      return
    }
    guard webView.url == nil,
      let range = buffer.range(
        of: #"http://127\.0\.0\.1:[0-9]+/\?token=[a-f0-9]+"#,
        options: .regularExpression),
      let url = URL(string: String(buffer[range]))
    else { return }
    serviceURL = url
    buffer = ""  // do not retain the bootstrap token in a log buffer
    webView.load(URLRequest(url: url))
  }

  func webView(
    _ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
    decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
  ) {
    guard let url = navigationAction.request.url, let local = serviceURL,
      url.scheme == local.scheme, url.host == local.host, url.port == local.port
    else {
      decisionHandler(.cancel)
      return
    }
    decisionHandler(.allow)
  }

  func webView(
    _ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
    initiatedByFrame frame: WKFrameInfo,
    completionHandler: @escaping ([URL]?) -> Void
  ) {
    let panel = NSOpenPanel()
    panel.allowsMultipleSelection = parameters.allowsMultipleSelection
    panel.canChooseDirectories = parameters.allowsDirectories
    panel.canChooseFiles = true
    panel.beginSheetModal(for: window) { response in
      completionHandler(response == .OK ? panel.urls : nil)
    }
  }

  private func showError(_ text: String) {
    webView.navigationDelegate = nil
    let escaped =
      text
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

@MainActor
func runApplication() {
  let app = NSApplication.shared
  app.setActivationPolicy(.regular)

  let mainMenu = NSMenu()

  let appItem = NSMenuItem()
  mainMenu.addItem(appItem)
  let appMenu = NSMenu()
  appMenu.addItem(
    withTitle: "About sm",
    action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
    keyEquivalent: "")
  appMenu.addItem(.separator())
  appMenu.addItem(
    withTitle: "Quit sm",
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
  editMenu.addItem(
    withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
  editItem.submenu = editMenu

  app.mainMenu = mainMenu

  let delegate = AppDelegate()
  app.delegate = delegate
  withExtendedLifetime(delegate) { app.run() }
}

// The executable's top-level entry point is on the macOS main thread.
MainActor.assumeIsolated { runApplication() }
