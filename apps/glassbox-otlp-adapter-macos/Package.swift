// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "GlassboxOTLPAdapterMacOS",
  platforms: [.macOS(.v13)],
  products: [.executable(name: "GlassboxOTLPAdapter", targets: ["GlassboxOTLPAdapter"])],
  targets: [
    .executableTarget(name: "GlassboxOTLPAdapter"),
    .testTarget(name: "GlassboxOTLPAdapterTests", dependencies: ["GlassboxOTLPAdapter"]),
  ]
)
