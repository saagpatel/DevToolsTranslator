import AppKit
import SwiftUI

final class GlassboxInstrumentsAdapterAppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
  }
}

@main
struct GlassboxInstrumentsAdapterApp: App {
  @NSApplicationDelegateAdaptor(GlassboxInstrumentsAdapterAppDelegate.self) private var appDelegate
  @StateObject private var store: InstrumentsAdapterStore

  init() {
    if CommandLine.arguments
      == [CommandLine.arguments[0], "--glassbox-instruments-har-project"]
    {
      exit(InstrumentsProjectionCommand.run())
    }
    _store = StateObject(wrappedValue: InstrumentsAdapterStore())
  }

  var body: some Scene {
    WindowGroup("Glassbox Instruments Adapter", id: "instruments-adapter") {
      InstrumentsContentView(store: store)
        .frame(minWidth: 720, minHeight: 520)
    }
    .defaultSize(width: 820, height: 620)
    .commands {
      CommandMenu("Convert") {
        Button("Convert Instruments Trace…") { store.chooseAndConvert() }
          .keyboardShortcut("o", modifiers: [.command])
          .disabled(!store.canConvert)
      }
    }
  }
}
