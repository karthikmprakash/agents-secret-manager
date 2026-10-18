// sm — native macOS shell for the local sm UI.
//
// The app starts the bundled `sm ui --no-open` binary, reads the loopback URL
// (with its session token) from stdout, and shows it in a WKWebView. The child
// process is terminated when the app quits or locks.
//
// Before the UI is shown, an app-level lock is required: Touch ID on supported
// Macs, or the desktop passphrase managed by `sm lock`. This gates the desktop
// app only; the vault identity still lives in the Keychain and the CLI/MCP are
// intentionally not gated by it.
import Cocoa
import LocalAuthentication
import WebKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
  private var window: NSWindow!
  private var webView: WKWebView!
  private var server: Process?
  private var buffer = ""
  private var serviceURL: URL?
  private var unlocked = false

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

    let workspace = NSWorkspace.shared.notificationCenter
    workspace.addObserver(self, selector: #selector(systemWillSleep), name: NSWorkspace.willSleepNotification, object: nil)
    DistributedNotificationCenter.default().addObserver(
      self, selector: #selector(screenLocked), name: NSNotification.Name("com.apple.screenIsLocked"), object: nil)

    requireUnlock()
  }

  // MARK: - App lock

  @objc func lockNow() {
    requireUnlock()
  }

  @objc private func systemWillSleep() {
    requireUnlock()
  }

  @objc private func screenLocked() {
    requireUnlock()
  }

  private func requireUnlock() {
    stopServer()
    unlocked = false
    webView.loadHTMLString(blankPage, baseURL: nil)
    if !lockConfigured() {
      promptSetup()
      return
    }
    tryBiometrics(fallbackToPassphrase: true)
  }

  private func lockConfigured() -> Bool {
    runSM(["lock", "status", "--quiet"], stdin: nil).status == 0
  }

  private func verifyPassphrase(_ passphrase: String) -> Bool {
    runSM(["lock", "verify", "--stdin", "--quiet"], stdin: passphrase + "\n").status == 0
  }

  private func setPassphrase(_ passphrase: String) -> Bool {
    runSM(["lock", "set", "--stdin"], stdin: passphrase + "\n").status == 0
  }

  private func biometricsAvailable() -> Bool {
    let context = LAContext()
    var error: NSError?
    return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
  }

  private func tryBiometrics(fallbackToPassphrase: Bool) {
    guard biometricsAvailable() else {
      if fallbackToPassphrase { promptPassphrase() }
      return
    }
    let context = LAContext()
    context.evaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      localizedReason: "Unlock sm"
    ) { [weak self] success, _ in
      DispatchQueue.main.async {
        guard let self else { return }
        if success {
          self.unlock()
        } else if fallbackToPassphrase {
          self.promptPassphrase()
        }
      }
    }
  }

  private func promptPassphrase() {
    while true {
      let alert = NSAlert()
      alert.messageText = "Unlock sm"
      alert.informativeText = "Enter your desktop passphrase."
      let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
      field.placeholderString = "Passphrase"
      alert.accessoryView = field
      alert.addButton(withTitle: "Unlock")
      let touchID = biometricsAvailable()
      if touchID { alert.addButton(withTitle: "Use Touch ID") }
      alert.addButton(withTitle: "Quit")

      switch alert.runModal() {
      case .alertFirstButtonReturn:
        if verifyPassphrase(field.stringValue) {
          unlock()
          return
        }
        showErrorAlert("Incorrect passphrase. Try again.")
      case .alertSecondButtonReturn where touchID:
        tryBiometrics(fallbackToPassphrase: true)
        return
      default:
        NSApp.terminate(nil)
        return
      }
    }
  }

  private func promptSetup() {
    while true {
      let alert = NSAlert()
      alert.messageText = "Create a desktop passphrase"
      alert.informativeText =
        "It protects this app. Touch ID can unlock it later on supported Macs. "
        + "The vault identity stays in the Keychain, so CLI and MCP are unchanged."
      let stack = NSStackView()
      stack.orientation = .vertical
      stack.spacing = 8
      let passphrase = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
      passphrase.placeholderString = "Passphrase (8+ characters)"
      let confirm = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
      confirm.placeholderString = "Confirm passphrase"
      stack.addArrangedSubview(passphrase)
      stack.addArrangedSubview(confirm)
      stack.frame = NSRect(x: 0, y: 0, width: 280, height: 56)
      alert.accessoryView = stack
      alert.addButton(withTitle: "Create")
      alert.addButton(withTitle: "Quit")

      guard alert.runModal() == .alertFirstButtonReturn else {
        NSApp.terminate(nil)
        return
      }
      if passphrase.stringValue.count < 8 {
        showErrorAlert("Use at least 8 characters.")
        continue
      }
      if passphrase.stringValue != confirm.stringValue {
        showErrorAlert("Passphrases do not match.")
        continue
      }
      if setPassphrase(passphrase.stringValue) {
        unlock()
        return
      }
      showErrorAlert("Could not save the desktop passphrase.")
    }
  }

  private func unlock() {
    unlocked = true
    window.contentView = webView
    startServer()
  }

  // MARK: - Local service

  private func smPath() -> String {
    let macos = Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS")
    return macos.appendingPathComponent("sm").path
  }

  /// runSM runs the bundled CLI with an optional passphrase on stdin. The
  /// passphrase never appears in argv or the environment.
  private func runSM(_ arguments: [String], stdin: String?) -> (status: Int32, output: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: smPath())
    process.arguments = arguments
    process.currentDirectoryURL = FileManager.default.homeDirectoryForCurrentUser
    let output = Pipe()
    let input = Pipe()
    process.standardOutput = output
    process.standardError = FileHandle.nullDevice
    if stdin != nil {
      process.standardInput = input
    }
    do {
      try process.run()
    } catch {
      return (127, "")
    }
    if let stdin {
      input.fileHandleForWriting.write(Data(stdin.utf8))
      input.fileHandleForWriting.closeFile()
    }
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
  }

  private func startServer() {
    guard server == nil else { return }
    serviceURL = nil
    buffer = ""
    let process = Process()
    process.executableURL = URL(fileURLWithPath: smPath())
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

  private func stopServer() {
    server?.terminate()
    server = nil
    serviceURL = nil
    buffer = ""
  }

  private func handleOutput(_ text: String) {
    guard unlocked, serviceURL == nil else { return }
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

  private let blankPage = """
    <html><body style="margin:0;background:#0b0d11"></body></html>
    """

  // MARK: - Web view delegates

  func webView(
    _ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
    decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
  ) {
    // Recovery archives are generated as encrypted blobs by our own origin.
    // Allow only explicit downloads, not arbitrary blob navigation.
    if navigationAction.shouldPerformDownload,
      let url = navigationAction.request.url, url.scheme == "blob",
      let local = serviceURL,
      url.absoluteString.hasPrefix("blob:http://127.0.0.1:\(local.port ?? 0)/") {
      decisionHandler(.download)
      return
    }
    guard unlocked, let url = navigationAction.request.url, let local = serviceURL,
      url.scheme == local.scheme, url.host == local.host, url.port == local.port
    else {
      decisionHandler(.cancel)
      return
    }
    decisionHandler(.allow)
  }

  func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
    download.delegate = self
  }

  func download(
    _ download: WKDownload, decideDestinationUsing response: URLResponse,
    suggestedFilename: String, completionHandler: @escaping (URL?) -> Void
  ) {
    let panel = NSSavePanel()
    panel.nameFieldStringValue = "sm-recovery.age"
    panel.message = "Save your encrypted recovery archive locally. Keep its passphrase separately."
    panel.beginSheetModal(for: window) { result in
      completionHandler(result == .OK ? panel.url : nil)
    }
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

  // MARK: - Errors

  private func showError(_ text: String) {
    if !unlocked {
      showErrorAlert(text)
      return
    }
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

  private func showErrorAlert(_ text: String) {
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = "sm"
    alert.informativeText = text
    alert.addButton(withTitle: "OK")
    alert.runModal()
  }

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    true
  }

  func applicationWillTerminate(_ notification: Notification) {
    stopServer()
  }
}

@MainActor
func runApplication() {
  let app = NSApplication.shared
  app.setActivationPolicy(.regular)

  let delegate = AppDelegate()
  app.delegate = delegate

  let mainMenu = NSMenu()

  let appItem = NSMenuItem()
  mainMenu.addItem(appItem)
  let appMenu = NSMenu()
  appMenu.addItem(
    withTitle: "About sm",
    action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
    keyEquivalent: "")
  appMenu.addItem(.separator())
  let lockItem = NSMenuItem(
    title: "Lock now", action: #selector(AppDelegate.lockNow), keyEquivalent: "l")
  lockItem.target = delegate
  appMenu.addItem(lockItem)
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
  withExtendedLifetime(delegate) { app.run() }
}

// The executable's top-level entry point is on the macOS main thread.
MainActor.assumeIsolated { runApplication() }
