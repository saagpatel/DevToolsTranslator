import Foundation
import Testing

@testable import Glassbox

@Suite("Native shell contract")
struct InvestigationModelsTests {
  @Test("unmarked drops fail closed")
  func unmarkedDropsFailClosed() throws {
    var payload = try fixturePayload()
    payload = NativeShellPayload(
      schemaVersion: payload.schemaVersion,
      kernel: payload.kernel,
      view: payload.view,
      rowPresentations: payload.rowPresentations,
      totalCount: payload.totalCount,
      visibleGapCount: payload.visibleGapCount,
      unmarkedDropCount: 1
    )
    #expect(throws: NativeShellError.unmarkedDrops) { try payload.validated() }
  }

  @Test("temporal candidates cannot become causal claims")
  func causalPromotionFailsClosed() throws {
    let payload = try fixturePayload(causalAssertion: true)
    #expect(throws: NativeShellError.causalPromotion) { try payload.validated() }
  }

  @Test("relationless imported evidence remains valid without inventing a relation")
  func relationlessImportIsValid() throws {
    let fixture = try fixturePayload()
    let view = InvestigationViewModel(
      scenarioId: "imported-evidence",
      family: "imported_evidence",
      variant: "import",
      scope: fixture.view.scope,
      permissionTier: fixture.view.permissionTier,
      privacyMode: fixture.view.privacyMode,
      limitations: fixture.view.limitations,
      anchors: fixture.view.anchors,
      actorLanes: fixture.view.actorLanes,
      evidenceTable: fixture.view.evidenceTable,
      relationExplanations: [],
      hypotheses: fixture.view.hypotheses,
      comparison: fixture.view.comparison,
      exportPreview: fixture.view.exportPreview,
      conclusion: fixture.view.conclusion,
      smallestSafeNextSource: fixture.view.smallestSafeNextSource)
    let payload = NativeShellPayload(
      schemaVersion: fixture.schemaVersion,
      kernel: KernelReceipt(inserted: 1, total: 1, relationCount: 0),
      view: view,
      rowPresentations: fixture.rowPresentations,
      totalCount: 1,
      visibleGapCount: 1,
      unmarkedDropCount: 0)
    #expect(try payload.validated() == payload)
    let presentation = try #require(payload.selectionPresentation(id: "e1"))
    #expect(presentation.label == "Event")
    #expect(presentation.status == .gap)
    #expect(presentation.relationship.summary == "No relationship is present for the selected evidence.")
    #expect(presentation.relationship.basis == "None recorded")
    #expect(presentation.relationship.supportingEvidence.isEmpty)
    #expect(!presentation.relationship.summary.localizedCaseInsensitiveContains("upload freeze"))
  }

  @Test("relationship presentation uses only referenced evidence fields")
  func relationshipPresentationIsPayloadDerived() throws {
    let payload = try fixturePayload()
    let presentation = try #require(payload.selectionPresentation(id: "e1"))
    #expect(presentation.relationship.summary == "Event → Event. This recorded relationship is non-causal.")
    #expect(presentation.relationship.basis == "Temporal Candidate · test/v1")
    #expect(presentation.relationship.uncertainty == "overlap")
    #expect(presentation.relationship.supportingEvidence == ["Event"])
    #expect(presentation.relationship.counterevidence.isEmpty)
    #expect(presentation.relationship.falsifier == "different timing")
    #expect(payload.displayTitle == "Test")
    #expect(payload.actorLaneOrder == ["Application"])
  }

  private func fixturePayload(causalAssertion: Bool = false) throws -> NativeShellPayload {
    let json = """
      {
        "schema_version":"glassbox-native-shell/v1",
        "kernel":{"inserted":2,"total":2,"relation_count":1},
        "view":{
          "scenario_id":"test","family":"test","variant":"base","scope":["fixture"],
          "permission_tier":"import_only","privacy_mode":"metadata","limitations":[{"kind":"gap","detail":"visible","affected_source":"fixture"}],
          "anchors":["e1"],"actor_lanes":{"Application":[{"id":"e1","actor":"Application","label":"Event","earliest_ns":"1","latest_ns":"2"}]},
          "evidence_table":[{"id":"e1","actor":"Application","label":"Event","time_range":"1..2","source":"fixture","native_locator":"fixture:1"}],
          "relation_explanations":[{"from":"e1","to":"e1","basis":"temporal_candidate","rule_version":"test/v1","uncertainty":"overlap","supporting_evidence":["e1"],"counterevidence":[],"missing_evidence":[],"falsifier":"different timing","causal_assertion":\(causalAssertion)}],
          "hypotheses":[{"id":"h","status":"correlated","statement":"candidate","premises":["e1"],"counterevidence":[],"missing_evidence":[],"falsifier":"different timing","model_generated":false}],
          "comparison":{"healthy_scenario":"healthy","differing_evidence":["e1"],"unchanged_evidence":[]},
          "export_preview":[{"field":"x","classification":"metadata","action":"preserve"}],"conclusion":"correlated","smallest_safe_next_source":null
        },
        "row_presentations":{"e1":{"time":"1","status":"gap","uncertainty":"known gap"}},
        "total_count":1,"visible_gap_count":1,"unmarked_drop_count":0
      }
      """
    let decoder = JSONDecoder()
    decoder.keyDecodingStrategy = .convertFromSnakeCase
    return try decoder.decode(NativeShellPayload.self, from: Data(json.utf8))
  }
}
