import Foundation

enum EvidenceStatus: String, Codable, CaseIterable, Sendable {
  case observed, correlated, inferred, unknown, gap

  var label: String {
    switch self {
    case .observed: "Observed"
    case .correlated: "Correlated"
    case .inferred: "Inferred"
    case .unknown: "Unknown"
    case .gap: "Gap / drop"
    }
  }
}

enum WorkspaceMode: String, CaseIterable, Identifiable {
  case timeline, table
  var id: Self { self }
  var label: String { self == .timeline ? "Timeline (actors)" : "Table (evidence)" }
}

struct KernelReceipt: Codable, Equatable, Sendable {
  let inserted: Int
  let total: Int
  let relationCount: Int
}

struct RowPresentation: Codable, Equatable, Sendable {
  let time: String
  let status: EvidenceStatus
  let uncertainty: String
}

struct EvidenceTableRow: Codable, Identifiable, Equatable, Sendable {
  let id: String
  let actor: String
  let label: String
  let timeRange: String
  let source: String
  let nativeLocator: String
}

struct TimelineItem: Codable, Identifiable, Equatable, Sendable {
  let id: String
  let actor: String
  let label: String
  let earliestNs: String
  let latestNs: String
}

struct ScenarioRelation: Codable, Equatable, Sendable {
  let from: String
  let to: String
  let basis: String
  let ruleVersion: String
  let uncertainty: String
  let supportingEvidence: [String]
  let counterevidence: [String]
  let missingEvidence: [String]
  let falsifier: String?
  let causalAssertion: Bool
}

struct Hypothesis: Codable, Identifiable, Equatable, Sendable {
  let id: String
  let status: EvidenceStatus
  let statement: String
  let premises: [String]
  let counterevidence: [String]
  let missingEvidence: [String]
  let falsifier: String?
  let modelGenerated: Bool
}

struct Limitation: Codable, Identifiable, Equatable, Sendable {
  var id: String { "\(kind):\(affectedSource)" }
  let kind: String
  let detail: String
  let affectedSource: String
}

struct RunComparison: Codable, Equatable, Sendable {
  let healthyScenario: String
  let differingEvidence: [String]
  let unchangedEvidence: [String]
}

struct ExportPreviewRow: Codable, Identifiable, Equatable, Sendable {
  var id: String { field }
  let field: String
  let classification: String
  let action: String
}

struct InvestigationViewModel: Codable, Equatable, Sendable {
  let scenarioId: String
  let family: String
  let variant: String
  let scope: [String]
  let permissionTier: String
  let privacyMode: String
  let limitations: [Limitation]
  let anchors: [String]
  let actorLanes: [String: [TimelineItem]]
  let evidenceTable: [EvidenceTableRow]
  let relationExplanations: [ScenarioRelation]
  let hypotheses: [Hypothesis]
  let comparison: RunComparison?
  let exportPreview: [ExportPreviewRow]
  let conclusion: EvidenceStatus
  let smallestSafeNextSource: String?
}

struct NativeShellPayload: Codable, Equatable, Sendable {
  let schemaVersion: String
  let kernel: KernelReceipt
  let view: InvestigationViewModel
  let rowPresentations: [String: RowPresentation]
  let totalCount: Int
  let visibleGapCount: Int
  let unmarkedDropCount: Int

  var displayTitle: String { view.scenarioId.evidenceDisplayText }

  var permissionTierLabel: String { view.permissionTier.evidenceDisplayText }

  var privacyModeLabel: String { view.privacyMode.evidenceDisplayText }

  var actorLaneOrder: [String] { view.actorLanes.keys.sorted() }

  var anchorLabel: String? {
    view.anchors.compactMap { evidenceRow(id: $0)?.label }.first
  }

  var uncertaintySummary: String {
    let values = Set(rowPresentations.values.map(\.uncertainty)).sorted()
    return values.isEmpty ? "Unknown" : values.joined(separator: " · ")
  }

  func evidenceRow(id: String) -> EvidenceTableRow? {
    view.evidenceTable.first(where: { $0.id == id })
  }

  func evidenceLabels(_ ids: [String]) -> [String] {
    ids.map { evidenceRow(id: $0)?.label ?? $0 }
  }

  func selectionPresentation(id: String) -> EvidenceSelectionPresentation? {
    guard let row = evidenceRow(id: id), let rowPresentation = rowPresentations[id] else {
      return nil
    }
    let relation = view.relationExplanations.first {
      [$0.from, $0.to].contains(id) || $0.supportingEvidence.contains(id)
        || $0.counterevidence.contains(id)
    }
    let relationship: RelationshipPresentation
    if let relation {
      let from = evidenceRow(id: relation.from)?.label ?? relation.from
      let to = evidenceRow(id: relation.to)?.label ?? relation.to
      relationship = RelationshipPresentation(
        summary: "\(from) → \(to). This recorded relationship is non-causal.",
        basis: "\(relation.basis.evidenceDisplayText) · \(relation.ruleVersion)",
        uncertainty: relation.uncertainty,
        supportingEvidence: evidenceLabels(relation.supportingEvidence),
        counterevidence: evidenceLabels(relation.counterevidence),
        missingEvidence: evidenceLabels(relation.missingEvidence),
        falsifier: relation.falsifier ?? "None recorded")
    } else {
      relationship = RelationshipPresentation(
        summary: "No relationship is present for the selected evidence.",
        basis: "None recorded",
        uncertainty: "None recorded",
        supportingEvidence: [],
        counterevidence: [],
        missingEvidence: [],
        falsifier: "None recorded")
    }
    return EvidenceSelectionPresentation(
      label: row.label,
      time: rowPresentation.time,
      status: rowPresentation.status,
      uncertainty: rowPresentation.uncertainty,
      source: row.source,
      nativeLocator: row.nativeLocator,
      relationship: relationship)
  }

  func validated() throws -> Self {
    guard schemaVersion == "glassbox-native-shell/v1" else { throw NativeShellError.invalidSchema }
    guard !view.evidenceTable.isEmpty, view.evidenceTable.count <= 200 else {
      throw NativeShellError.unboundedPage
    }
    let ids = Set(view.evidenceTable.map(\.id))
    guard totalCount >= view.evidenceTable.count else { throw NativeShellError.countMismatch }
    guard ids.count == view.evidenceTable.count, Set(rowPresentations.keys) == ids else {
      throw NativeShellError.incompletePresentation
    }
    let visualIds = Set(view.actorLanes.values.flatMap { $0 }.map(\.id))
    guard visualIds == ids else { throw NativeShellError.timelineTableMismatch }
    guard unmarkedDropCount == 0 else { throw NativeShellError.unmarkedDrops }
    guard visibleGapCount == rowPresentations.values.filter({ $0.status == .gap }).count else {
      throw NativeShellError.gapCountMismatch
    }
    guard kernel.inserted > 0, kernel.total >= kernel.inserted else {
      throw NativeShellError.kernelReceiptMissing
    }
    guard view.relationExplanations.allSatisfy({ !$0.causalAssertion }) else {
      throw NativeShellError.causalPromotion
    }
    let relationReferences = view.relationExplanations.flatMap {
      [$0.from, $0.to] + $0.supportingEvidence + $0.counterevidence
    }
    let hypothesisReferences = view.hypotheses.flatMap { $0.premises + $0.counterevidence }
    let comparisonReferences =
      (view.comparison?.differingEvidence ?? []) + (view.comparison?.unchangedEvidence ?? [])
    guard
      (view.anchors + relationReferences + hypothesisReferences + comparisonReferences).allSatisfy(
        ids.contains)
    else { throw NativeShellError.invalidEvidenceReference }
    return self
  }
}

struct RelationshipPresentation: Equatable, Sendable {
  let summary: String
  let basis: String
  let uncertainty: String
  let supportingEvidence: [String]
  let counterevidence: [String]
  let missingEvidence: [String]
  let falsifier: String
}

struct EvidenceSelectionPresentation: Equatable, Sendable {
  let label: String
  let time: String
  let status: EvidenceStatus
  let uncertainty: String
  let source: String
  let nativeLocator: String
  let relationship: RelationshipPresentation
}

private extension String {
  var evidenceDisplayText: String {
    replacingOccurrences(of: "_", with: " ")
      .replacingOccurrences(of: "-", with: " ")
      .split(separator: " ")
      .map { $0.prefix(1).uppercased() + $0.dropFirst() }
      .joined(separator: " ")
  }
}

enum NativeShellError: LocalizedError, Equatable {
  case helperUnavailable
  case helperFailed(String)
  case helperTimedOut, helperOutputTooLarge
  case invalidImportProbe
  case invalidOutput, invalidSchema, unboundedPage
  case incompletePresentation, timelineTableMismatch, unmarkedDrops, gapCountMismatch
  case kernelReceiptMissing, causalPromotion, countMismatch, invalidEvidenceReference

  var errorDescription: String? {
    switch self {
    case .helperUnavailable: "The signed Rust evidence helper is unavailable."
    case .helperFailed(let message): "The Rust evidence helper failed: \(message)"
    case .helperTimedOut: "The Rust evidence helper exceeded its bounded execution time."
    case .helperOutputTooLarge: "The Rust evidence helper exceeded its bounded output size."
    case .invalidImportProbe: "The import verification probe is incomplete."
    case .invalidOutput: "The Rust evidence helper returned invalid output."
    case .invalidSchema: "The native shell payload schema is not recognized."
    case .unboundedPage: "The evidence page exceeds its bounded contract."
    case .incompletePresentation: "Evidence presentation metadata is incomplete or duplicated."
    case .timelineTableMismatch: "The actor timeline and evidence table disagree."
    case .unmarkedDrops: "The evidence payload contains an unmarked drop."
    case .gapCountMismatch: "The visible gap count does not match the evidence rows."
    case .kernelReceiptMissing: "The evidence payload is not backed by a kernel import receipt."
    case .causalPromotion: "A temporal candidate was promoted to a causal claim."
    case .countMismatch: "The declared evidence count is smaller than the bounded page."
    case .invalidEvidenceReference:
      "A relationship or hypothesis points outside the bounded evidence page."
    }
  }
}
