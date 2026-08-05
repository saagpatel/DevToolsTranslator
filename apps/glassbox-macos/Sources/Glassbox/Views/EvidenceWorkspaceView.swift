import SwiftUI

struct EvidenceWorkspaceView: View {
  @ObservedObject var store: InvestigationStore
  let payload: NativeShellPayload

  private var selection: EvidenceSelectionPresentation? {
    payload.selectionPresentation(id: store.selectedID)
  }

  var body: some View {
    VStack(spacing: 0) {
      HStack {
        Picker("Evidence view", selection: $store.mode) {
          ForEach(WorkspaceMode.allCases) { mode in Text(mode.label).tag(mode) }
        }
        .pickerStyle(.segmented)
        .frame(maxWidth: 320)
        .accessibilityIdentifier("glassbox-evidence-mode")
        Spacer()
        Text("\(store.filteredRows.count) of \(payload.totalCount) events · paused")
          .font(.caption.monospacedDigit())
          .foregroundStyle(.secondary)
      }
      .padding(10)

      VSplitView {
        EvidenceTimelineView(store: store, payload: payload)
          .frame(
            minHeight: store.mode == .timeline ? 260 : 0,
            idealHeight: store.mode == .timeline ? 340 : 0,
            maxHeight: store.mode == .timeline ? .infinity : 0
          )
          .opacity(store.mode == .timeline ? 1 : 0)
          .allowsHitTesting(store.mode == .timeline)
          .accessibilityHidden(store.mode != .timeline)
          .clipped()
        EvidenceTableView(store: store, payload: payload)
          .frame(minHeight: 240)
      }

      HStack {
        Text("Anchor: \(payload.anchorLabel ?? "None recorded")")
        Spacer()
        Label(
          "\(selection?.uncertainty ?? "Unknown uncertainty") · conclusion: \(payload.view.conclusion.label)",
          systemImage: "exclamationmark.triangle"
        )
        .foregroundStyle(.orange)
      }
      .font(.caption)
      .padding(.horizontal, 10)
      .frame(height: 30)
      .background(.bar)
    }
    .onChange(of: store.mode) { mode in
      store.acknowledgeProbeRender(code: mode == .table ? "t" : "l")
    }
    .onChange(of: store.selectedID) { _ in
      store.acknowledgeProbeRender(code: "s")
    }
  }
}

struct EvidenceTimelineView: View {
  @ObservedObject var store: InvestigationStore
  let payload: NativeShellPayload

  var body: some View {
    ScrollView([.horizontal, .vertical]) {
      Grid(alignment: .leading, horizontalSpacing: 0, verticalSpacing: 0) {
        GridRow {
          Text("Actor lane").frame(width: 150, alignment: .leading)
          Text("Each event displays its evidence-provided time")
          .font(.caption2.monospaced())
          .foregroundStyle(.secondary)
          .frame(width: 760, alignment: .leading)
        }.padding(.vertical, 6)
        ForEach(payload.actorLaneOrder, id: \.self) { lane in
          GridRow {
            VStack(alignment: .leading, spacing: 2) {
              Text(lane).fontWeight(.medium)
              Text("\(payload.view.actorLanes[lane]?.count ?? 0) evidence items")
                .font(.caption2).foregroundStyle(.secondary)
            }
            .frame(width: 150, height: 62, alignment: .leading)
            HStack(spacing: 8) {
              ForEach(payload.view.actorLanes[lane] ?? []) { item in
                Button {
                  store.selectedID = item.id
                } label: {
                  VStack(alignment: .leading, spacing: 3) {
                    Text(item.label).lineLimit(1)
                    Text(payload.rowPresentations[item.id]?.time ?? item.earliestNs)
                      .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
                  }
                  .frame(width: 132, alignment: .leading)
                  .padding(7)
                }
                .buttonStyle(.bordered)
                .tint(item.id == store.selectedID ? .purple : statusColor(item.id))
                .accessibilityLabel(
                  "\(item.label), \(payload.rowPresentations[item.id]?.status.label ?? "Unknown")")
              }
              Spacer(minLength: 0)
            }
            .frame(width: 760, height: 62, alignment: .leading)
          }
          Divider().gridCellUnsizedAxes(.horizontal)
        }
      }
      .padding(.horizontal, 10)
    }
    .accessibilityLabel("Actor-lane evidence timeline")
  }

  private func statusColor(_ id: String) -> Color {
    switch payload.rowPresentations[id]?.status {
    case .gap: .red
    case .unknown: .gray
    case .correlated: .purple
    default: .cyan
    }
  }
}

struct EvidenceTableView: View {
  @ObservedObject var store: InvestigationStore
  let payload: NativeShellPayload

  var body: some View {
    Table(
      store.filteredRows,
      selection: Binding<String?>(
        get: { store.selectedID },
        set: { if let value = $0 { store.selectedID = value } }
      )
    ) {
      TableColumn("Time (UTC)") { row in
        Text(payload.rowPresentations[row.id]?.time ?? row.timeRange).font(
          .system(.caption, design: .monospaced))
      }
      .width(min: 95, ideal: 105)
      TableColumn("Actor", value: \.actor).width(min: 90, ideal: 115)
      TableColumn("Source", value: \.source).width(min: 85, ideal: 105)
      TableColumn("Native locator") { row in
        Text(row.nativeLocator).font(.system(.caption, design: .monospaced)).lineLimit(1)
      }
      .width(min: 130, ideal: 190)
      TableColumn("Event", value: \.label).width(min: 130, ideal: 220)
      TableColumn("Claim") { row in
        Text(payload.rowPresentations[row.id]?.status.label ?? "Unknown").foregroundStyle(
          claimColor(row.id))
      }
      .width(min: 75, ideal: 90)
      TableColumn("Uncertainty") { row in
        Text(payload.rowPresentations[row.id]?.uncertainty ?? "unknown").font(
          .system(.caption, design: .monospaced))
      }
      .width(min: 90, ideal: 120)
    }
    .accessibilityLabel("Complete tabular equivalent of the actor-lane timeline")
    .accessibilityIdentifier("glassbox-evidence-table")
  }

  private func claimColor(_ id: String) -> Color {
    switch payload.rowPresentations[id]?.status {
    case .gap: .red
    case .unknown: .secondary
    case .correlated: .purple
    default: .cyan
    }
  }
}
