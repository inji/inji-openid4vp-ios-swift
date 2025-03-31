// swift-tools-version: 5.9.0

import PackageDescription

let package = Package(
    name: "OpenID4VP",
    platforms: [
        .iOS(.v14)
    ],
    products: [
        .library(
            name: "OpenID4VP",
            targets: ["OpenID4VP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/beatt83/jose-swift.git", .upToNextMinor(from: "4.0.2"))
    ],
    targets: [
        .target(
            name: "OpenID4VP",
            dependencies: [
                "jose-swift"
            ]),
        .testTarget(
            name: "OpenID4VPTests",
            dependencies: ["OpenID4VP","jose-swift"]),
    ]
)
