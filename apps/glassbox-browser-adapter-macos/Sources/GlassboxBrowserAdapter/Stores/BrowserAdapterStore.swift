import AppKit
import Foundation
import UniformTypeIdentifiers

@MainActor
final class BrowserAdapterStore: ObservableObject {
  @Published private(set) var items: [BrowserEvidenceItem] = []
  @Published var selectedID: BrowserEvidenceItem.ID?
  @Published private(set) var status: BrowserAdapterStatus = .ready("Ready. No operation is active.")

  private let files = BrowserAdapterFileService()

  init() { refresh() }

  var selected: BrowserEvidenceItem? { items.first { $0.id == selectedID } }
  var canExport: Bool { selected != nil }

  func refresh() {
    do {
      items = try files.items()
      if !items.contains(where: { $0.id == selectedID }) { selectedID = items.first?.id }
      status = .ready(items.isEmpty ? "No completed selected-tab evidence is waiting." : "Completed evidence is ready for explicit export.")
    } catch { fail("The private browser evidence inbox could not be read.") }
  }

  func installManifest() {
    do {
      try files.installManifest(hostURL: try hostURL())
      status = .ready("Native Messaging manifest installed for the exact Glassbox extension ID.")
    } catch { fail(error.localizedDescription) }
  }

  func resetManifest() {
    do {
      try files.resetManifest()
      status = .ready("Native Messaging manifest removed. Existing user exports were preserved.")
    } catch { fail(error.localizedDescription) }
  }

  func exportSelected() {
    guard let selected else { return }
    let panel = NSSavePanel()
    panel.title = "Export Browser Evidence"
    panel.message = "Choose a new file. Existing files are never overwritten."
    panel.nameFieldStringValue = selected.url.lastPathComponent
    panel.canCreateDirectories = true
    if let type = UTType(filenameExtension: "glassbox") { panel.allowedContentTypes = [type] }
    guard panel.runModal() == .OK, let destination = panel.url else { return }
    do {
      try files.export(item: selected, to: destination)
      status = .ready("Export complete. Import the bundle into the offline Glassbox core.")
    } catch { fail(error.localizedDescription) }
  }

  func deleteSelected() {
    guard let selected else { return }
    let alert = NSAlert()
    alert.messageText = "Delete app-owned browser evidence?"
    alert.informativeText = "This deletes only the selected inbox copy. User exports are never removed."
    alert.addButton(withTitle: "Delete Inbox Copy")
    alert.addButton(withTitle: "Cancel")
    guard alert.runModal() == .alertFirstButtonReturn else { return }
    do {
      try files.deleteOwned(item: selected)
      refresh()
    } catch { fail(error.localizedDescription) }
  }

  private func hostURL() throws -> URL {
    let url = Bundle.main.bundleURL
      .appendingPathComponent("Contents/Helpers/glassbox-browser-host")
    guard FileManager.default.isExecutableFile(atPath: url.path) else {
      throw BrowserAdapterFileError.invalidHost
    }
    return url
  }

  private func fail(_ message: String) { status = .failed(message) }
}
