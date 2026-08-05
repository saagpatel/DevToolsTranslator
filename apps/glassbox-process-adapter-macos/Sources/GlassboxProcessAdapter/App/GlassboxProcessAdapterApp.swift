import AppKit
import SwiftUI

final class GlassboxProcessAdapterAppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
  }
}

@main
struct GlassboxProcessAdapterApp: App {
  @NSApplicationDelegateAdaptor(GlassboxProcessAdapterAppDelegate.self) private var appDelegate
  @StateObject private var store = ProcessAdapterStore()

  var body: some Scene {
    WindowGroup("Glassbox Process Context", id: "process-context") {
      ProcessContentView(store: store)
        .frame(minWidth: 760, minHeight: 620)
    }
    .defaultSize(width: 860, height: 700)
    .commands {
      CommandMenu("Capture") {
        Button("Refresh Running Applications") { store.refreshCandidates() }
          .keyboardShortcut("r", modifiers: [.command])
          .disabled(!store.canRefresh)
        Button("Start Selected Capture…") { store.startCapture() }
          .keyboardShortcut("p", modifiers: [.command, .shift])
          .disabled(!store.canStart)
        Button("Stop and Save Capture") { store.stopCapture() }
          .keyboardShortcut(".", modifiers: [.command])
          .disabled(!store.canStop)
        Button("Cancel and Discard Capture") { store.cancelCapture() }
          .disabled(!store.canCancel)
      }
    }
  }
}
