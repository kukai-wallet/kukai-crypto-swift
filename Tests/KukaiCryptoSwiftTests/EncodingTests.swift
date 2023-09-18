//
//  EncodingTests.swift
//  
//
//  Created by Simon Mcloughlin on 18/09/2023.
//

import XCTest
@testable import KukaiCryptoSwift

final class EncodingTests: XCTestCase {
	
	func testBase58CheckEncodeAndDecode() throws {
		
		let base58_1 = "edpkvCbYCa6d6g9hEcK6tvwgsY9jfB4HDzp3jZSBwfuWNSvxE5T5KR"
		let base58_2 = "sppk7bXQFZLFWSLusY6gzH9NfbFWT6c61d5vb5zxNZycThMk1qMtPwk"
		let base58_3 = "edpkuC1VC96abMGC9uhGi8zfAkEM3AH4bd5H6jiHeA9kZXD4gzVKCY"
		let base58_4 = "sppk7b2poW37GfMQTbeRpFAKrhisSobBW6Ece49cKJzkDDfaT2maXRy"
		
		let decode1 = Base58Check.decode(string: base58_1, prefix: Prefix.Keys.Ed25519.public)
		let decode1Hex = decode1?.hexString ?? ""
		let decode2 = Base58Check.decode(string: base58_2, prefix: Prefix.Keys.Secp256k1.public)
		let decode2Hex = decode2?.hexString ?? ""
		let decode3 = Base58Check.decode(string: base58_3, prefix: Prefix.Keys.Ed25519.public)
		let decode3Hex = decode3?.hexString ?? ""
		let decode4 = Base58Check.decode(string: base58_4, prefix: Prefix.Keys.Secp256k1.public)
		let decode4Hex = decode4?.hexString ?? ""
		
		XCTAssert(decode1Hex == "cd33a22f74d8e04977f74db15a0b1e92d21a59f351e987b9fd462bf6ef2dc253", decode1Hex)
		XCTAssert(decode2Hex == "032460b1fb47abc6b64bfa313efdba92eb4313f58b90ac30b68851b4880cc9c819", decode2Hex)
		XCTAssert(decode3Hex == "482c29dcbfc1f94c185e9d8da1ee7e06b16239a5d4e15a64a6f4150c298ab029", decode3Hex)
		XCTAssert(decode4Hex == "02e37da4dd8966a3f6941e81f72e884e47687a79f2cfe55c903f9acb2c94c8936f", decode4Hex)
		
		
		
		let encode1 = Base58Check.encode(message: decode1 ?? [], prefix: Prefix.Keys.Ed25519.public)
		let encode2 = Base58Check.encode(message: decode2 ?? [], prefix: Prefix.Keys.Secp256k1.public)
		let encode3 = Base58Check.encode(message: decode3 ?? [], prefix: Prefix.Keys.Ed25519.public)
		let encode4 = Base58Check.encode(message: decode4 ?? [], prefix: Prefix.Keys.Secp256k1.public)
		
		XCTAssert(encode1 == base58_1, encode1)
		XCTAssert(encode2 == base58_2, encode2)
		XCTAssert(encode3 == base58_3, encode3)
		XCTAssert(encode4 == base58_4, encode4)
		
		
		
		let message1 = Base58Check.encode(message: "testing something encodeable 1".bytes, ellipticalCurve: .ed25519)
		let message2 = Base58Check.encode(message: "testing something encodeable 2".bytes, ellipticalCurve: .secp256k1)
		let message3 = Base58Check.encode(message: "testing something encodeable 3".bytes, ellipticalCurve: .ed25519)
		let message4 = Base58Check.encode(message: "testing something encodeable 4".bytes, ellipticalCurve: .secp256k1)
		
		XCTAssert(message1 == "7WBtn3E9RBK4PtEoP15sYTiSgLL89fFJmQEAbd9HBgTWThM7PTcza", message1)
		XCTAssert(message2 == "9nNmTC8QADXQZCcSV25iGHxJZZcMHPayRZ7dqsLxoeKYdetf3FyPT", message2)
		XCTAssert(message3 == "7WBtn3E9RBK4PtEoP15sYTiSgLL89fFJmQEAbd9HBgTWThMHT1FF6", message3)
		XCTAssert(message4 == "9nNmTC8QADXQZCcSV25iGHxJZZcMHPayRZ7dqsLxoeKYdetwZjsv1", message4)
		
		let decodedMessage1 = Base58Check.decode(string: message1, prefix: Prefix.Keys.Ed25519.signature) ?? []
		let data1 = Data(bytes: decodedMessage1, count: decodedMessage1.count)
		let decodedMessage2 = Base58Check.decode(string: message2, prefix: Prefix.Keys.Secp256k1.signature) ?? []
		let data2 = Data(bytes: decodedMessage2, count: decodedMessage1.count)
		let decodedMessage3 = Base58Check.decode(string: message3, prefix: Prefix.Keys.Ed25519.signature) ?? []
		let data3 = Data(bytes: decodedMessage3, count: decodedMessage1.count)
		let decodedMessage4 = Base58Check.decode(string: message4, prefix: Prefix.Keys.Secp256k1.signature) ?? []
		let data4 = Data(bytes: decodedMessage4, count: decodedMessage1.count)
		
		XCTAssert(String(data: data1, encoding: .utf8) == "testing something encodeable 1", decodedMessage1.hexString)
		XCTAssert(String(data: data2, encoding: .utf8) == "testing something encodeable 2", decodedMessage1.hexString)
		XCTAssert(String(data: data3, encoding: .utf8) == "testing something encodeable 3", decodedMessage1.hexString)
		XCTAssert(String(data: data4, encoding: .utf8) == "testing something encodeable 4", decodedMessage1.hexString)
	}
}
