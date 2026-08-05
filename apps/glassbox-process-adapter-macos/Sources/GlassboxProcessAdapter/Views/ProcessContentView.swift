import AppKit
import SwiftUI

struct ProcessContentView: View {
  @ObservedObject var store: ProcessAdapterStore

  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      VStack(alignment: .leading, spacing: 5) {
        Label("Glassbox Process Context", systemImage: "cpu")
          .font(.title.bold())
        Text("A separate, ordinary-permission adapter for one explicitly selected GUI application.")
          .foregroundStyle(.secondary)
      }
      GroupBox("Evidence boundary") {
        VStack(alignment: .leading, spacing: 7) {
          Label("Retains only the selected bundle identifier, cumulative CPU time, memory, wakeups, and terminal coverage.", systemImage: "checkmark.seal")
          Label("Drops PID, executable path, arguments, username, environment, files, disk activity, and network activity.", systemImage: "eye.slash")
          Label("The helper authenticates process continuity, but the bundle identifier remains a user-selected controller claim.", systemImage: "person.badge.key")
          Label("Resource overlap is context only—never cause or process-to-network attribution.", systemImage: "exclamationmark.triangle")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 3)
      }
      HStack {
        Text("Running applications").font(.headline)
        Spacer()
        Button("Refresh", systemImage: "arrow.clockwise") { store.refreshCandidates() }
          .disabled(!store.canRefresh)
      }
      List(store.candidates, selection: $store.selectedID) { candidate in
        VStack(alignment: .leading, spacing: 2) {
          Text(candidate.displayName)
          Text(candidate.bundleIdentifier).font(.caption).foregroundStyle(.secondary)
        }
        .tag(candidate.id)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(candidate.displayName), \(candidate.bundleIdentifier)")
      }
      .frame(minHeight: 180)
      HStack(spacing: 10) {
        Image(systemName: statusSymbol).foregroundStyle(statusColor)
        VStack(alignment: .leading, spacing: 2) {
          Text(store.phase.label).font(.headline)
          if case let .failed(message) = store.phase { Text(message).foregroundStyle(.red) }
          else if !store.destinationName.isEmpty { Text(store.destinationName).foregroundStyle(.secondary) }
        }
        Spacer()
        if store.phase == .capturing || store.phase == .stopping || store.phase == .cancelling {
          ProgressView().controlSize(.small)
        }
      }
      if store.phase == .completed, let receipt = store.receipt {
        GroupBox("Validated evidence") {
          LabeledContent("Observations", value: receipt.observations.formatted())
          LabeledContent("Relations", value: receipt.relations.formatted())
          LabeledContent("Bundle size", value: ByteCountFormatter.string(fromByteCount: Int64(receipt.bundleBytes), countStyle: .file))
          LabeledContent("SHA-256", value: receipt.bundleSHA256).textSelection(.enabled)
        }
      }
      HStack {
        Text("Import the completed bundle in Glassbox with File → Import Evidence.")
          .font(.callout).foregroundStyle(.secondary)
        Spacer()
        if store.canCancel {
          Button("Cancel and Discard", role: .destructive) { store.cancelCapture() }
        }
        if store.canStop {
          Button("Stop and Save") { store.stopCapture() }
            .keyboardShortcut(.defaultAction)
        } else if store.canStart {
          Button(store.phase == .completed ? "Capture Again…" : "Start Capture…") {
            store.startCapture()
          }
          .keyboardShortcut(.defaultAction)
          .accessibilityIdentifier("glassbox-process-start")
        }
      }
    }
    .padding(26)
    .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
      store.cancelCapture()
    }
  }

  private var statusSymbol: String {
    switch store.phase {
    case .ready, .completed: "checkmark.circle.fill"
    case .capturing, .stopping, .cancelling: "hourglass"
    case .failed: "exclamationmark.triangle.fill"
    default: "circle.dotted"
    }
  }

  private var statusColor: Color {
    switch store.phase {
    case .ready, .completed: .green
    case .capturing, .stopping, .cancelling: .orange
    case .failed: .red
    default: .secondary
    }
  }
}
