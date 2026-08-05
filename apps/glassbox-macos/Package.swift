// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "GlassboxMacOS",
    platforms: [.macOS(.v13)],
    products: [.executable(name: "Glassbox", targets: ["Glassbox"])],
    targets: [
        .executableTarget(name: "Glassbox"),
        .testTarget(name: "GlassboxTests", dependencies: ["Glassbox"]),
    ]
)

