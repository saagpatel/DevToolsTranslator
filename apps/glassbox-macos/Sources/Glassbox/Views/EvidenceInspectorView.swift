import SwiftUI

struct EvidenceInspectorView: View {
  @ObservedObject var store: InvestigationStore
  let payload: NativeShellPayload

  private var presentation: EvidenceSelectionPresentation? {
    payload.selectionPresentation(id: store.selectedID)
  }

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 16) {
        GroupBox("Why are these linked?") {
          InspectorField(
            title: "Relation",
            value: presentation?.relationship.summary
              ?? "No selected evidence is available."
          )
          InspectorField(
            title: "Basis", value: presentation?.relationship.basis ?? "None recorded")
          InspectorField(
            title: "Relationship uncertainty",
            value: presentation?.relationship.uncertainty ?? "None recorded")
          InspectorList(
            title: "Supporting evidence",
            values: presentation?.relationship.supportingEvidence ?? [])
          InspectorList(
            title: "Counterevidence",
            values: presentation?.relationship.counterevidence ?? [])
          InspectorList(
            title: "Missing evidence", values: presentation?.relationship.missingEvidence ?? [])
          InspectorField(
            title: "Falsifier", value: presentation?.relationship.falsifier ?? "None recorded")
          Divider()
          LabeledContent(
            "Selected evidence status", value: presentation?.status.label ?? "Unknown")
          LabeledContent("Investigation conclusion", value: payload.view.conclusion.label)
        }

        GroupBox("Competing hypotheses") {
          ForEach(payload.view.hypotheses) { hypothesis in
            VStack(alignment: .leading, spacing: 3) {
              Text(hypothesis.statement).fontWeight(.medium)
              Text(
                "\(hypothesis.status.label) · \(hypothesis.premises.count) support · \(hypothesis.counterevidence.count) counter"
              )
              .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if hypothesis.id != payload.view.hypotheses.last?.id { Divider() }
          }
        }

        GroupBox("Healthy-run comparison") {
          if let comparison = payload.view.comparison {
            LabeledContent("Healthy scenario", value: comparison.healthyScenario)
            LabeledContent("Differing evidence", value: "\(comparison.differingEvidence.count)")
            LabeledContent("Unchanged evidence", value: "\(comparison.unchangedEvidence.count)")
          } else {
            Text("No comparison is present in the evidence.")
              .font(.caption).foregroundStyle(.secondary)
          }
        }
      }
      .padding()
    }
    .accessibilityLabel("Evidence relationship inspector")
  }
}

private struct InspectorField: View {
  let title: String
  let value: String
  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      Text(title.uppercased()).font(.caption2).foregroundStyle(.secondary)
      Text(value).font(.caption)
    }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 3)
  }
}

private struct InspectorList: View {
  let title: String
  let values: [String]
  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      Text(title.uppercased()).font(.caption2).foregroundStyle(.secondary)
      if values.isEmpty {
        Text("None recorded").font(.caption).foregroundStyle(.secondary)
      } else {
        ForEach(values, id: \.self) { Text("• \($0)").font(.caption) }
      }
    }.frame(maxWidth: .infinity, alignment: .leading).padding(.vertical, 3)
  }
}
