// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "KukaiCryptoSwift",
	platforms: [
		.iOS("15.0"),
		.macOS("10.15"),
	],
    products: [
        .library(
            name: "KukaiCryptoSwift",
            targets: ["KukaiCryptoSwift"]
		),
    ],
	dependencies: [
		.package(url: "https://github.com/jedisct1/swift-sodium", from: "0.9.1"),
		.package(url: "https://github.com/Boilertalk/secp256k1.swift", from: "0.1.7"),
		.package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
		
		// Documentation plugin, only needed for github action
		.package(url: "https://github.com/apple/swift-docc-plugin", from: "1.3.0")
	],
    targets: [
        .target(
            name: "KukaiCryptoSwift",
			dependencies: [
				.product(name: "Clibsodium", package: "swift-sodium"),
				.product(name: "Sodium", package: "swift-sodium"),
				.product(name: "secp256k1", package: "secp256k1.swift"),
				"BigInt"
			]
		),
        .testTarget(
            name: "KukaiCryptoSwiftTests",
            dependencies: ["KukaiCryptoSwift"]
		),
    ]
)
