// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "GlassboxBrowserAdapterMacOS",
  platforms: [.macOS(.v13)],
  products: [.executable(name: "GlassboxBrowserAdapter", targets: ["GlassboxBrowserAdapter"])],
  targets: [
    .executableTarget(name: "GlassboxBrowserAdapter"),
    .testTarget(name: "GlassboxBrowserAdapterTests", dependencies: ["GlassboxBrowserAdapter"]),
  ]
)
