import AppKit
import SwiftUI

final class GlassboxOTLPAdapterAppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
  }
}

@main
struct GlassboxOTLPAdapterApp: App {
  @NSApplicationDelegateAdaptor(GlassboxOTLPAdapterAppDelegate.self) private var appDelegate
  @StateObject private var store = OTLPAdapterStore()

  var body: some Scene {
    WindowGroup("Glassbox OTLP Adapter", id: "adapter") {
      AdapterContentView(store: store)
        .frame(minWidth: 720, minHeight: 560)
    }
    .defaultSize(width: 820, height: 640)
    .commands {
      CommandMenu("Capture") {
        Button("Start Capture…") { store.startCapture() }
          .keyboardShortcut("r", modifiers: [.command, .shift])
          .disabled(!store.canStart)
        Button("Stop Capture") { store.stopCapture() }
          .keyboardShortcut(".", modifiers: [.command])
          .disabled(!store.canStop)
      }
    }
  }
}
