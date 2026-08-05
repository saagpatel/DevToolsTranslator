import SwiftUI

struct PassiveContentView: View {
  @ObservedObject var store: PassiveAdapterStore

  var body: some View {
    VStack(alignment: .leading, spacing: 22) {
      VStack(alignment: .leading, spacing: 6) {
        Label("Glassbox Passive Context", systemImage: "point.3.filled.connected.trianglepath.dotted")
          .font(.title.bold())
        Text("A separate, one-shot reader of this Mac’s ordinary neighbor-table cache.")
          .foregroundStyle(.secondary)
      }
      GroupBox("Evidence boundary") {
        VStack(alignment: .leading, spacing: 8) {
          Label("Runs only the fixed /usr/sbin/arp -an command. It sends no packets and performs no scan.", systemImage: "shield")
          Label("Retains only neighbor count, reachability state, conflicts, and explicit limitations.", systemImage: "checkmark.seal")
          Label("Drops IP addresses, link-layer identifiers, interfaces, ownership, processes, and services.", systemImage: "eye.slash")
          Label("Context is untrusted and noncausal. It never proves topology, identity, attribution, or cause.", systemImage: "exclamationmark.triangle")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
      }
      HStack(spacing: 12) {
        Image(systemName: statusSymbol).foregroundStyle(statusColor)
        VStack(alignment: .leading, spacing: 2) {
          Text(store.phase.label).font(.headline)
          if case let .failed(message) = store.phase { Text(message).foregroundStyle(.red) }
          else if !store.destinationName.isEmpty { Text(store.destinationName).foregroundStyle(.secondary) }
        }
        Spacer()
        if store.phase == .capturing || store.phase == .cancelling {
          ProgressView().controlSize(.small)
        }
      }
      .accessibilityElement(children: .combine)
      .accessibilityLabel("Passive context status: \(store.phase.label)")
      if store.phase == .completed, let receipt = store.receipt {
        GroupBox("Validated evidence") {
          LabeledContent("Observations", value: receipt.observations.formatted())
          LabeledContent("Relations", value: receipt.relations.formatted())
          LabeledContent("Bundle size", value: ByteCountFormatter.string(fromByteCount: Int64(receipt.bundleBytes), countStyle: .file))
          LabeledContent("SHA-256", value: receipt.bundleSHA256).textSelection(.enabled)
        }
      }
      Spacer(minLength: 8)
      HStack {
        Text("Import the completed bundle in Glassbox with File → Import Evidence.")
          .font(.callout).foregroundStyle(.secondary)
        Spacer()
        if store.canCancel {
          Button("Cancel", action: store.cancelCapture)
            .keyboardShortcut(.cancelAction)
            .accessibilityIdentifier("glassbox-passive-cancel")
        } else {
          Button(store.phase == .completed ? "Capture Again…" : "Capture Passive Context…", action: store.startCapture)
            .keyboardShortcut(.defaultAction)
            .disabled(!store.canStart)
            .accessibilityIdentifier("glassbox-passive-start")
        }
      }
    }
    .padding(28)
  }

  private var statusSymbol: String {
    switch store.phase {
    case .idle, .completed: "checkmark.circle.fill"
    case .capturing, .cancelling: "hourglass"
    case .failed: "exclamationmark.triangle.fill"
    default: "circle.dotted"
    }
  }

  private var statusColor: Color {
    switch store.phase {
    case .idle, .completed: .green
    case .capturing, .cancelling: .orange
    case .failed: .red
    default: .secondary
    }
  }
}
