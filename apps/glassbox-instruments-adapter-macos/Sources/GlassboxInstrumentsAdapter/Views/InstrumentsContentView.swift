import SwiftUI

struct InstrumentsContentView: View {
  @ObservedObject var store: InstrumentsAdapterStore

  var body: some View {
    VStack(alignment: .leading, spacing: 20) {
      VStack(alignment: .leading, spacing: 5) {
        Label("Glassbox Instruments Adapter", systemImage: "waveform.path.ecg.rectangle")
          .font(.title.bold())
        Text("A separate, ordinary-permission converter for user-selected Instruments traces.")
          .foregroundStyle(.secondary)
      }
      GroupBox("Evidence boundary") {
        VStack(alignment: .leading, spacing: 8) {
          Label(
            "Accepts one explicit .trace package and invokes only Xcode's supported xctrace HAR exporter.",
            systemImage: "checkmark.seal")
          Label(
            "Uses bounded, link-free staging with a fixed timeout and removes app-owned temporary files.",
            systemImage: "lock.shield")
          Label(
            "Has no entitlements and is never embedded in or launched by the App-Sandboxed Glassbox core.",
            systemImage: "rectangle.portrait.and.arrow.right")
          Label(
            "HAR can contain sensitive HTTP metadata; review, import, and securely remove it when no longer needed.",
            systemImage: "exclamationmark.triangle")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
      }
      HStack(spacing: 10) {
        Image(systemName: statusSymbol).foregroundStyle(statusColor)
        VStack(alignment: .leading, spacing: 3) {
          Text(store.phase.label).font(.headline)
          if case .failed(let message) = store.phase {
            Text(message).foregroundStyle(.red)
          } else if !store.sourceName.isEmpty {
            Text("\(store.sourceName) → \(store.destinationName)")
              .foregroundStyle(.secondary)
          }
        }
        Spacer()
        if store.phase == .converting { ProgressView().controlSize(.small) }
      }
      Spacer()
      HStack {
        Text("Import the completed HAR in Glassbox with File → Import Evidence.")
          .font(.callout)
          .foregroundStyle(.secondary)
        Spacer()
        Button(store.phase == .completed ? "Convert Another Trace…" : "Convert Trace…") {
          store.chooseAndConvert()
        }
        .keyboardShortcut(.defaultAction)
        .disabled(!store.canConvert)
        .accessibilityIdentifier("glassbox-instruments-convert")
      }
    }
    .padding(26)
  }

  private var statusSymbol: String {
    switch store.phase {
    case .ready, .completed: "checkmark.circle.fill"
    case .converting: "hourglass"
    case .failed: "exclamationmark.triangle.fill"
    }
  }

  private var statusColor: Color {
    switch store.phase {
    case .ready, .completed: .green
    case .converting: .orange
    case .failed: .red
    }
  }
}
