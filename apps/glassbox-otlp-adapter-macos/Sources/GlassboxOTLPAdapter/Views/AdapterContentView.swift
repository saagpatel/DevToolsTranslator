import SwiftUI

struct AdapterContentView: View {
  @ObservedObject var store: OTLPAdapterStore

  var body: some View {
    VStack(alignment: .leading, spacing: 22) {
      header
      disclosure
      status
      connection
      Spacer(minLength: 8)
      actions
    }
    .padding(28)
    .accessibilityElement(children: .contain)
  }

  private var header: some View {
    VStack(alignment: .leading, spacing: 6) {
      Label("Glassbox OTLP Adapter", systemImage: "point.3.connected.trianglepath.dotted")
        .font(.title.bold())
      Text("A separate, loopback-only source adapter for explicitly instrumented local apps.")
        .foregroundStyle(.secondary)
    }
  }

  private var disclosure: some View {
    GroupBox("Capture boundary") {
      VStack(alignment: .leading, spacing: 8) {
        Label("Receives OTLP traces only on this Mac through a one-use credential.", systemImage: "lock.shield")
        Label("Keeps trace IDs, timing, parent links, gaps, and explicit limitations.", systemImage: "checkmark.seal")
        Label("Drops span names, attributes, resource values, credentials, and unknown content.", systemImage: "eye.slash")
        Label("Writes only a complete kernel-validated .glassbox bundle; invalid input writes nothing.", systemImage: "shippingbox")
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.vertical, 4)
    }
  }

  private var status: some View {
    HStack(spacing: 12) {
      Image(systemName: statusSymbol)
        .foregroundStyle(statusColor)
      VStack(alignment: .leading, spacing: 2) {
        Text(store.phase.label).font(.headline)
        if case let .failed(message) = store.phase {
          Text(message).foregroundStyle(.red)
        } else if !store.destinationName.isEmpty {
          Text(store.destinationName).foregroundStyle(.secondary)
        }
      }
      Spacer()
      if store.phase == .starting || store.phase == .stopping {
        ProgressView().controlSize(.small)
      }
    }
    .accessibilityElement(children: .combine)
    .accessibilityLabel("Adapter status: \(store.phase.label)")
  }

  @ViewBuilder
  private var connection: some View {
    if store.phase == .listening {
      GroupBox("Instrumented app connection") {
        VStack(alignment: .leading, spacing: 12) {
          connectionRow(label: "Endpoint", value: store.endpoint, copy: store.copyEndpoint)
          connectionRow(label: "One-use credential", value: store.credential, copy: store.copyCredential)
          Text("Pass the credential in the Glassbox framed session—not in a URL, command history, log, or telemetry field.")
            .font(.callout)
            .foregroundStyle(.secondary)
        }
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 4)
      }
    } else if store.phase == .completed, let receipt = store.receipt {
      GroupBox("Validated evidence") {
        LabeledContent("Observations", value: receipt.observations.formatted())
        LabeledContent("Relations", value: receipt.relations.formatted())
        LabeledContent("Bundle size", value: ByteCountFormatter.string(fromByteCount: Int64(receipt.bundleBytes), countStyle: .file))
        LabeledContent("SHA-256", value: receipt.bundleSHA256)
          .textSelection(.enabled)
      }
    }
  }

  private func connectionRow(label: String, value: String, copy: @escaping () -> Void) -> some View {
    HStack(alignment: .firstTextBaseline) {
      VStack(alignment: .leading, spacing: 3) {
        Text(label).font(.caption).foregroundStyle(.secondary)
        Text(value).font(.system(.body, design: .monospaced))
      }
      Spacer()
      Button("Copy", action: copy)
        .accessibilityLabel("Copy \(label)")
    }
  }

  private var actions: some View {
    HStack {
      Text("Import the completed bundle in Glassbox with File → Import Evidence.")
        .font(.callout)
        .foregroundStyle(.secondary)
      Spacer()
      if store.canStop {
        Button("Stop and Validate", action: store.stopCapture)
          .keyboardShortcut(.defaultAction)
          .accessibilityIdentifier("glassbox-otlp-stop")
      } else {
        Button(store.phase == .completed ? "Start Another Capture…" : "Start Capture…", action: store.startCapture)
          .keyboardShortcut(.defaultAction)
          .disabled(!store.canStart)
          .accessibilityIdentifier("glassbox-otlp-start")
      }
    }
  }

  private var statusSymbol: String {
    switch store.phase {
    case .idle, .completed: "checkmark.circle.fill"
    case .listening: "record.circle"
    case .failed: "exclamationmark.triangle.fill"
    default: "hourglass"
    }
  }

  private var statusColor: Color {
    switch store.phase {
    case .idle, .completed: .green
    case .listening: .orange
    case .failed: .red
    default: .secondary
    }
  }
}
