import SwiftUI

struct ScopeSidebarView: View {
  @ObservedObject var store: InvestigationStore
  let payload: NativeShellPayload

  private var selection: EvidenceSelectionPresentation? {
    payload.selectionPresentation(id: store.selectedID)
  }

  var body: some View {
    List {
      Section("Sources (\(store.enabledSources.count) of \(payload.view.scope.count))") {
        ForEach(payload.view.scope, id: \.self) { source in
          Toggle(
            source,
            isOn: Binding(
              get: { store.enabledSources.contains(source) },
              set: { _ in store.toggleSource(source) }
            ))
        }
      }
      Section("Capture boundary") {
        LabeledContent("Permission", value: payload.permissionTierLabel)
        LabeledContent("Privacy", value: payload.privacyModeLabel)
        LabeledContent("Sources", value: "\(payload.view.scope.count)")
        VStack(alignment: .leading, spacing: 2) {
          Text("Clock uncertainty").fontWeight(.medium)
          Text(payload.uncertaintySummary).font(.caption).foregroundStyle(.secondary)
        }
      }
      Section("Coverage limitations") {
        ForEach(payload.view.limitations) { limitation in
          VStack(alignment: .leading, spacing: 2) {
            Text(limitation.kind.capitalized).fontWeight(.medium)
            Text(limitation.detail).font(.caption).foregroundStyle(.secondary)
          }
        }
      }
      Section("Selected evidence") {
        Text(selection?.label ?? "None").fontWeight(.semibold)
        Text(selection?.time ?? "Unknown")
          .font(.caption.monospaced()).foregroundStyle(.secondary)
        LabeledContent("Status", value: selection?.status.label ?? "Unknown")
        LabeledContent("Source", value: selection?.source ?? "Unknown")
      }
    }
    .listStyle(.sidebar)
    .navigationTitle("Scope & limits")
  }
}
