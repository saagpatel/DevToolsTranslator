import AppKit
import SwiftUI

final class GlassboxPassiveAdapterAppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
  }
}

@main
struct GlassboxPassiveAdapterApp: App {
  @NSApplicationDelegateAdaptor(GlassboxPassiveAdapterAppDelegate.self) private var appDelegate
  @StateObject private var store = PassiveAdapterStore()

  var body: some Scene {
    WindowGroup("Glassbox Passive Context", id: "passive-context") {
      PassiveContentView(store: store)
        .frame(minWidth: 720, minHeight: 560)
    }
    .defaultSize(width: 820, height: 640)
    .commands {
      CommandMenu("Context") {
        Button("Capture Passive Context…") { store.startCapture() }
          .keyboardShortcut("p", modifiers: [.command, .shift])
          .disabled(!store.canStart)
        Button("Cancel Capture") { store.cancelCapture() }
          .keyboardShortcut(".", modifiers: [.command])
          .disabled(!store.canCancel)
      }
    }
  }
}
