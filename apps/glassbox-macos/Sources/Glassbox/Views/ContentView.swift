import SwiftUI

struct ContentView: View {
  @ObservedObject var store: InvestigationStore

  var body: some View {
    Group {
      if let payload = store.payload {
        InvestigationWorkbench(store: store, payload: payload)
      } else if let error = store.loadError {
        VStack(spacing: 12) {
          Image(systemName: "exclamationmark.shield").font(.system(size: 36)).foregroundStyle(
            .orange)
          Text("Evidence unavailable").font(.title2).fontWeight(.semibold)
          Text(error.localizedDescription).foregroundStyle(.secondary).multilineTextAlignment(
            .center)
        }
        .padding(30)
        .accessibilityIdentifier("glassbox-fail-closed-error")
      } else {
        ProgressView("Validating evidence kernel…")
      }
    }
    .sheet(isPresented: $store.exportPresented) {
      if let payload = store.payload { ExportReviewView(rows: payload.view.exportPreview) }
    }
    .alert(
      "Import rejected",
      isPresented: Binding(
        get: { store.importErrorMessage != nil },
        set: { if !$0 { store.importErrorMessage = nil } })
    ) {
      Button("OK", role: .cancel) { store.importErrorMessage = nil }
    } message: {
      Text(store.importErrorMessage ?? "The evidence import was rejected.")
    }
    .onChange(of: store.exportPresented) { presented in
      store.acknowledgeProbeRender(code: presented ? "o" : "c")
    }
    .task { await store.runInteractionProbeIfRequested() }
  }
}

private struct InvestigationWorkbench: View {
  @ObservedObject var store: InvestigationStore
  let payload: NativeShellPayload

  var body: some View {
    HSplitView {
      NavigationSplitView {
        ScopeSidebarView(store: store, payload: payload)
          .navigationSplitViewColumnWidth(min: 190, ideal: 220, max: 260)
      } detail: {
        EvidenceWorkspaceView(store: store, payload: payload)
      }
      EvidenceInspectorView(store: store, payload: payload)
        .frame(minWidth: 280, idealWidth: 340, maxWidth: 420)
    }
    .navigationTitle(payload.displayTitle)
    .searchable(text: $store.searchText, placement: .toolbar, prompt: "Search evidence")
    .toolbar {
      ToolbarItemGroup {
        Button("Import", systemImage: "square.and.arrow.down") {
          Task { await store.importEvidence() }
        }
        .disabled(store.isImporting || store.isSamplingResources)
        .help("Import through the isolated Rust evidence boundary")
        .accessibilityIdentifier("glassbox-import-evidence")
        if store.isImporting {
          ProgressView().controlSize(.small).accessibilityLabel("Importing evidence")
        }
        Button(
          store.isSamplingResources ? "Stop sampling" : "Sample system",
          systemImage: store.isSamplingResources ? "stop.circle" : "gauge.with.dots.needle.33percent"
        ) {
          store.toggleResourceSampler()
        }
        .disabled(store.isImporting)
        .help(
          "Collect bounded system load and memory context for at most 30 seconds. No process identities or network activity are collected; context is not cause."
        )
        .accessibilityIdentifier("glassbox-resource-sampler")
        if store.isSamplingResources {
          ProgressView().controlSize(.small).accessibilityLabel(store.resourceSamplerStatus)
        }
        Button("Export review", systemImage: "square.and.arrow.up") { store.exportPresented = true }
          .accessibilityIdentifier("glassbox-export-review")
      }
    }
  }
}
