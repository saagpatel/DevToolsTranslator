// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "GlassboxInstrumentsAdapterMacOS",
  platforms: [.macOS(.v13)],
  products: [
    .executable(name: "GlassboxInstrumentsAdapter", targets: ["GlassboxInstrumentsAdapter"])
  ],
  targets: [
    .executableTarget(name: "GlassboxInstrumentsAdapter"),
    .testTarget(
      name: "GlassboxInstrumentsAdapterTests",
      dependencies: ["GlassboxInstrumentsAdapter"]),
  ]
)
