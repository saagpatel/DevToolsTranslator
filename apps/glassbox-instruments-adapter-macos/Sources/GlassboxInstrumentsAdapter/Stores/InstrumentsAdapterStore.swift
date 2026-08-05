import AppKit
import Darwin
import Foundation
import UniformTypeIdentifiers

enum InstrumentsAdapterPhase: Equatable {
  case ready
  case converting
  case completed
  case failed(String)

  var label: String {
    switch self {
    case .ready: "Ready"
    case .converting: "Converting with Xcode Instruments"
    case .completed: "HAR export ready"
    case .failed: "Conversion failed"
    }
  }
}

@MainActor
final class InstrumentsAdapterStore: ObservableObject {
  @Published private(set) var phase: InstrumentsAdapterPhase = .ready
  @Published private(set) var sourceName = ""
  @Published private(set) var destinationName = ""

  var canConvert: Bool { phase != .converting }

  func chooseAndConvert() {
    guard canConvert else { return }
    let openPanel = NSOpenPanel()
    openPanel.title = "Choose an Instruments Network Trace"
    openPanel.message = "Select one non-sensitive .trace package recorded with Instruments Network."
    openPanel.allowsMultipleSelection = false
    openPanel.canChooseFiles = true
    openPanel.canChooseDirectories = true
    openPanel.treatsFilePackagesAsDirectories = false
    guard openPanel.runModal() == .OK, let source = openPanel.url,
      source.pathExtension == "trace"
    else { return }

    let savePanel = NSSavePanel()
    savePanel.title = "Save Temporary HAR for Glassbox Import"
    savePanel.message =
      "HAR can contain sensitive HTTP metadata. Import it into Glassbox, then securely remove it when no longer needed."
    savePanel.nameFieldStringValue = "Glassbox Instruments Export.har"
    savePanel.canCreateDirectories = true
    if let har = UTType(filenameExtension: "har") { savePanel.allowedContentTypes = [har] }
    guard savePanel.runModal() == .OK, let destination = savePanel.url else { return }
    guard !FileManager.default.fileExists(atPath: destination.path) else {
      phase = .failed("Choose a new destination; existing files are never overwritten.")
      return
    }

    phase = .converting
    sourceName = source.lastPathComponent
    destinationName = destination.lastPathComponent
    Task {
      let result = await Task.detached(priority: .userInitiated) {
        Result { try Self.convert(source: source, destination: destination) }
      }.value
      switch result {
      case .success: phase = .completed
      case .failure:
        try? FileManager.default.removeItem(at: destination)
        phase = .failed(
          "The trace was rejected or compatible Xcode command-line tools were unavailable.")
      }
    }
  }

  nonisolated private static func convert(source: URL, destination: URL) throws {
    let sourceDescriptor = open(source.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard sourceDescriptor >= 0 else { throw InstrumentsConversionError.invalidSource }
    defer { close(sourceDescriptor) }
    let destinationDescriptor = open(
      destination.path,
      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
      S_IRUSR | S_IWUSR)
    guard destinationDescriptor >= 0 else { throw InstrumentsConversionError.outputInvalid }
    let output = FileHandle(fileDescriptor: destinationDescriptor, closeOnDealloc: true)
    do {
      try InstrumentsConversionService.convert(sourceDescriptor: sourceDescriptor, to: output)
      try output.synchronize()
      try output.close()
    } catch {
      try? output.close()
      throw error
    }
  }
}
