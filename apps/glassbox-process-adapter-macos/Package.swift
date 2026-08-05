// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "GlassboxProcessAdapterMacOS",
  platforms: [.macOS(.v13)],
  products: [.executable(name: "GlassboxProcessAdapter", targets: ["GlassboxProcessAdapter"])],
  targets: [
    .executableTarget(name: "GlassboxProcessAdapter"),
    .testTarget(name: "GlassboxProcessAdapterTests", dependencies: ["GlassboxProcessAdapter"]),
  ]
)
