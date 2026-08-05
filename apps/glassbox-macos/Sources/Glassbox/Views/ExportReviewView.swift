import SwiftUI

struct ExportReviewView: View {
  @Environment(\.dismiss) private var dismiss
  let rows: [ExportPreviewRow]

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      HStack {
        Text("Export / redaction preview").font(.title2).fontWeight(.semibold)
        Spacer()
        Button("Close") { dismiss() }.keyboardShortcut(.cancelAction)
      }
      Text("Derived export · authenticity: unsigned_local").foregroundStyle(.secondary)
      Table(rows) {
        TableColumn("Field", value: \.field)
        TableColumn("Class", value: \.classification)
        TableColumn("Action", value: \.action)
      }
      HStack {
        Spacer()
        Button("Create derived package") {}
          .buttonStyle(.borderedProminent)
          .disabled(true)
          .help("Package creation remains owned by the validated privacy/export boundary")
      }
    }
    .padding(20)
    .frame(minWidth: 620, minHeight: 420)
    .accessibilityIdentifier("glassbox-export-review-sheet")
  }
}
