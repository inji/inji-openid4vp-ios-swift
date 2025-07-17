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
        .package(url: "https://github.com/beatt83/jose-swift.git", "4.0.2"..<"4.0.3"),
        .package(url: "https://github.com/Alamofire/Alamofire.git", "5.10.2"..<"5.10.3"),
        .package(url: "https://github.com/valpackett/SwiftCBOR.git",  "0.5.0"..<"0.5.1"),
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", "2.1.7"..<"2.1.8")
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
