// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Prefunk",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "PrefunkCore", targets: ["PrefunkCore"]),
        .executable(name: "PrefunkMac", targets: ["PrefunkMac"]),
        .executable(name: "prefunk", targets: ["PrefunkCLI"])
    ],
    targets: [
        .target(name: "PrefunkCore", path: "Sources/PrefunkCore"),
        .executableTarget(
            name: "PrefunkMac",
            dependencies: ["PrefunkCore"],
            path: "Sources/PrefunkMac"
        ),
        .executableTarget(name: "PrefunkCLI", dependencies: ["PrefunkCore"], path: "Sources/PrefunkCLI")
    ]
)
