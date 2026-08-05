// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "GlassboxPassiveAdapterMacOS",
  platforms: [.macOS(.v13)],
  products: [.executable(name: "GlassboxPassiveAdapter", targets: ["GlassboxPassiveAdapter"])],
  targets: [
    .executableTarget(name: "GlassboxPassiveAdapter"),
    .testTarget(name: "GlassboxPassiveAdapterTests", dependencies: ["GlassboxPassiveAdapter"]),
  ]
)
