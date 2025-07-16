// swift-tools-version: 5.9.0

import PackageDescription

let package = Package(
    name: "OpenID4VP",
    platforms: [
        .iOS(.v14),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "OpenID4VP",
            targets: ["OpenID4VP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/beatt83/jose-swift.git", .upToNextMinor(from: "4.0.2")),
        .package(url: "https://github.com/Alamofire/Alamofire.git", .upToNextMajor(from: "5.10.0")),
        .package(url: "https://github.com/valpackett/SwiftCBOR.git",  .upToNextMajor(from: "0.5.0")),
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", exact: "2.1.0")
    ],
    targets: [
        .target(
            name: "OpenID4VP",
            dependencies: [
                "jose-swift", "Alamofire", "SwiftCBOR", "Base58Swift"
            ]
        ),
        .testTarget(
            name: "OpenID4VPTests",
            dependencies: [
                "OpenID4VP", "jose-swift", "Alamofire", "SwiftCBOR", "Base58Swift"
            ]
        )
    ]
)
