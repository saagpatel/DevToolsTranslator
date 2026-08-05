import SwiftUI

struct BrowserAdapterView: View {
  @ObservedObject var store: BrowserAdapterStore

  var body: some View {
    VStack(alignment: .leading, spacing: 18) {
      VStack(alignment: .leading, spacing: 5) {
        Label("Glassbox Browser Adapter", systemImage: "network")
          .font(.title.bold())
        Text("A separate Native Messaging adapter for one explicitly inspected Chrome tab.")
          .foregroundStyle(.secondary)
      }
      GroupBox("Trust and privacy boundary") {
        VStack(alignment: .leading, spacing: 7) {
          Label("Chrome starts the signed host only for the exact extension origin in its user-scoped manifest.", systemImage: "checkmark.seal")
          Label("The DevTools panel is the persistent capture indicator and binds capture to its inspected tab.", systemImage: "rectangle.and.hand.point.up.left")
          Label("Headers, cookies, credentials, bodies, raw hosts, paths, and query values are never retained.", systemImage: "eye.slash")
          Label("Browser evidence is signed-untrusted or user-asserted context; it never proves cause.", systemImage: "exclamationmark.triangle")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 3)
      }
      HStack {
        Button("Install Native Messaging Manifest") { store.installManifest() }
        Button("Reset Connection", role: .destructive) { store.resetManifest() }
        Spacer()
        Button("Refresh Inbox", systemImage: "arrow.clockwise") { store.refresh() }
      }
      Text("Install or load the Glassbox Selected Tab extension separately, open Chrome DevTools for the chosen tab, then use its visible Glassbox panel.")
        .font(.callout).foregroundStyle(.secondary)
      List(store.items, selection: $store.selectedID) { item in
        HStack {
          VStack(alignment: .leading, spacing: 2) {
            Text(item.url.lastPathComponent)
            Text(item.modified.formatted()).font(.caption).foregroundStyle(.secondary)
          }
          Spacer()
          Text(ByteCountFormatter.string(fromByteCount: item.bytes, countStyle: .file))
            .foregroundStyle(.secondary)
        }
        .tag(item.id)
        .accessibilityElement(children: .combine)
      }
      .frame(minHeight: 180)
      HStack {
        Image(systemName: statusSymbol)
          .foregroundStyle(statusColor)
        Text(store.status.message)
        Spacer()
        Button("Delete Inbox Copy", role: .destructive) { store.deleteSelected() }
          .disabled(!store.canExport)
        Button("Export Selected…") { store.exportSelected() }
          .keyboardShortcut(.defaultAction)
          .disabled(!store.canExport)
          .accessibilityIdentifier("glassbox-browser-export")
      }
    }
    .padding(26)
  }

  private var statusSymbol: String {
    if case .failed = store.status { return "exclamationmark.triangle.fill" }
    return "checkmark.circle.fill"
  }

  private var statusColor: Color {
    if case .failed = store.status { return .red }
    return .green
  }
}
