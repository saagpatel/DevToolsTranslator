import AppKit
import SwiftUI

final class GlassboxBrowserAdapterAppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
  }
}

@main
struct GlassboxBrowserAdapterApp: App {
  @NSApplicationDelegateAdaptor(GlassboxBrowserAdapterAppDelegate.self) private var appDelegate
  @StateObject private var store = BrowserAdapterStore()

  var body: some Scene {
    WindowGroup("Glassbox Browser Adapter", id: "browser-adapter") {
      BrowserAdapterView(store: store).frame(minWidth: 760, minHeight: 620)
    }
    .defaultSize(width: 860, height: 700)
    .commands {
      CommandMenu("Browser Evidence") {
        Button("Refresh Inbox") { store.refresh() }
          .keyboardShortcut("r", modifiers: [.command])
        Button("Export Selected Evidence…") { store.exportSelected() }
          .keyboardShortcut("e", modifiers: [.command, .shift])
          .disabled(!store.canExport)
        Divider()
        Button("Install Native Messaging Manifest") { store.installManifest() }
        Button("Reset Native Messaging Connection", role: .destructive) { store.resetManifest() }
      }
    }
  }
}
