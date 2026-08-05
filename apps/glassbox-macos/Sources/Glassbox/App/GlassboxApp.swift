import AppKit
import SwiftUI

final class GlassboxAppDelegate: NSObject, NSApplicationDelegate {
  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.regular)
    NSApp.activate(ignoringOtherApps: true)
  }
}

@main
struct GlassboxApp: App {
  @NSApplicationDelegateAdaptor(GlassboxAppDelegate.self) private var appDelegate
  @StateObject private var store: InvestigationStore

  init() {
    if CommandLine.arguments == [CommandLine.arguments[0], "--glassbox-apple-log-project"] {
      exit(AppleLogProjectionCommand.run())
    }
    if CommandLine.arguments == [CommandLine.arguments[0], "--glassbox-instruments-har-project"] {
      exit(InstrumentsTraceProjectionCommand.run())
    }
    _store = StateObject(wrappedValue: InvestigationStore())
  }

  var body: some Scene {
    WindowGroup("Glassbox", id: "investigation") {
      ContentView(store: store)
        .frame(minWidth: 1_024, minHeight: 680)
    }
    .defaultSize(width: 1_440, height: 900)
    .commands {
      CommandMenu("Investigation") {
        Button("Import Evidence…") { Task { await store.importEvidence() } }
          .keyboardShortcut("i", modifiers: [.command])
          .disabled(store.isImporting || store.isSamplingResources)
        Button(store.isSamplingResources ? "Stop System Sample" : "Sample System Resources") {
          store.toggleResourceSampler()
        }
        .keyboardShortcut("r", modifiers: [.command, .shift])
        .disabled(store.isImporting)
        Divider()
        Picker("Evidence View", selection: $store.mode) {
          ForEach(WorkspaceMode.allCases) { mode in Text(mode.label).tag(mode) }
        }
        Divider()
        Button("Export Review…") { store.exportPresented = true }
          .keyboardShortcut("e", modifiers: [.command, .shift])
          .disabled(store.payload == nil)
      }
    }
  }
}
