//
//  KeyPairTests.swift
//  
//
//  Created by Simon Mcloughlin on 10/06/2022.
//

import XCTest
@testable import KukaiCryptoSwift

final class KeyPairTests: XCTestCase {
	
	func testRegular() throws {
		let messageToSign = "something very interesting that needs to be signed".bytes
		let watermarkedBytes = messageToSign.addOperationWatermarkAndHash() ?? []
		let mnemonic = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform")
		
		let keyPair1 = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "", andSigningCurve: .ed25519)
		XCTAssert(keyPair1?.privateKey.bytes.hexString == "80d4e52897c8e14fbfad4637373de405fa2cc7f27eb9f890db975948b0e7fdb0cd33a22f74d8e04977f74db15a0b1e92d21a59f351e987b9fd462bf6ef2dc253", keyPair1?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair1?.publicKey.bytes.hexString == "cd33a22f74d8e04977f74db15a0b1e92d21a59f351e987b9fd462bf6ef2dc253", keyPair1?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair1?.publicKey.publicKeyHash == "tz1T3QZ5w4K11RS3vy4TXiZepraV9R5GzsxG", keyPair1?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair1?.publicKey.base58CheckRepresentation == "edpkvCbYCa6d6g9hEcK6tvwgsY9jfB4HDzp3jZSBwfuWNSvxE5T5KR", keyPair1?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair1?.privateKey.sign(bytes: watermarkedBytes)?.hexString == "c4d20c77d627d8c07e3f26ddc2e8ab9324471c65f9abd412de70a81c21ddc153dcfad1b31ab777a83c4e8a5dc021ea30d84da107dea4a192fc2ca9da9b3ede00",
				  keyPair1?.privateKey.sign(bytes: watermarkedBytes)?.hexString ?? "-")
		
		let keyPair2 = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "", andSigningCurve: .secp256k1)
		XCTAssert(keyPair2?.privateKey.bytes.hexString == "80d4e52897c8e14fbfad4637373de405fa2cc7f27eb9f890db975948b0e7fdb0", keyPair2?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair2?.publicKey.bytes.hexString == "032460b1fb47abc6b64bfa313efdba92eb4313f58b90ac30b68851b4880cc9c819", keyPair2?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair2?.publicKey.publicKeyHash == "tz2UiZQJwaVAKxRuYxV8Tx5k8a64gZx1ZwYJ", keyPair2?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair2?.publicKey.base58CheckRepresentation == "sppk7bXQFZLFWSLusY6gzH9NfbFWT6c61d5vb5zxNZycThMk1qMtPwk", keyPair2?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair2?.privateKey.sign(bytes: watermarkedBytes)?.hexString == "699bc6f9f3ad5987e02b5b2dfccfa86c5583be632bd60840abd5a14c94fb7dea43e39d1f08b8d406a26bf2de337313e8dad054a26b93fec76063e24bde6b8495",
				  keyPair2?.privateKey.sign(bytes: watermarkedBytes)?.hexString ?? "-")
		
		let keyPair3 = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "superSecurePassphrase", andSigningCurve: .ed25519)
		XCTAssert(keyPair3?.privateKey.bytes.hexString == "b17877f6b326bf75e8a5bf2bd7e457a03b103d469c869ef4e3b0473d9b9d50b1482c29dcbfc1f94c185e9d8da1ee7e06b16239a5d4e15a64a6f4150c298ab029", keyPair3?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair3?.publicKey.bytes.hexString == "482c29dcbfc1f94c185e9d8da1ee7e06b16239a5d4e15a64a6f4150c298ab029", keyPair3?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair3?.publicKey.publicKeyHash == "tz1hQ4wkVfNAh3eGeaDpoTBmQ9KjX9ZMzc6q", keyPair3?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair3?.publicKey.base58CheckRepresentation == "edpkuC1VC96abMGC9uhGi8zfAkEM3AH4bd5H6jiHeA9kZXD4gzVKCY", keyPair3?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair3?.privateKey.sign(bytes: watermarkedBytes)?.hexString == "f83f6075f87269ae141843bda4867942e4f9f7a299289eaed7f2185ad1ad0bb71e5b976e5a3169b32756d5d87a05875d2d3fc3615cc1509ab05c46df8d30b705",
				  keyPair3?.privateKey.sign(bytes: watermarkedBytes)?.hexString ?? "-")
		
		let keyPair4 = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "superSecurePassphrase", andSigningCurve: .secp256k1)
		XCTAssert(keyPair4?.privateKey.bytes.hexString == "b17877f6b326bf75e8a5bf2bd7e457a03b103d469c869ef4e3b0473d9b9d50b1", keyPair4?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair4?.publicKey.bytes.hexString == "02e37da4dd8966a3f6941e81f72e884e47687a79f2cfe55c903f9acb2c94c8936f", keyPair4?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair4?.publicKey.publicKeyHash == "tz2J2VKJaVRBwFs96hRiSAqHjJmRmqGirKv8", keyPair4?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair4?.publicKey.base58CheckRepresentation == "sppk7b2poW37GfMQTbeRpFAKrhisSobBW6Ece49cKJzkDDfaT2maXRy", keyPair4?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair4?.privateKey.sign(bytes: watermarkedBytes)?.hexString == "1f19dd5887c4e739377f1303db66bc12863942bc969ea29055152ddf7f25d32c0e8ff3ea8ac18ab58f328b830debad43e78cbf483dad38441301f59e6af633fa",
				  keyPair4?.privateKey.sign(bytes: watermarkedBytes)?.hexString ?? "-")
	}
	
	func testHD() throws {
		let messageToSign = "something very interesting that needs to be signed".bytes
		let watermarkedBytes = messageToSign.addOperationWatermarkAndHash() ?? []
		let mnemonic = try Mnemonic(seedPhrase: "gym exact clown can answer hope sample mirror knife twenty powder super imitate lion churn almost shed chalk dust civil gadget pyramid helmet trade")
		
		let keyPair1 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "", andDerivationPath: "44'/1729'/0'/0'")
		XCTAssert(keyPair1?.privateKey.bytes.hexString == "7b0c9fc748c9c784d50152fd2db370522a8727a8ec68fd0b7ef456330e2e089c66dc7517defa76d4355280505068b59172a568cacbd46c1f5f91a247c29426bc", keyPair1?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair1?.publicKey.bytes.hexString == "66dc7517defa76d4355280505068b59172a568cacbd46c1f5f91a247c29426bc", keyPair1?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair1?.publicKey.publicKeyHash == "tz1TyyX7U6r6tB1uSS4aUnfKX9rj3y9NCEVL", keyPair1?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair1?.publicKey.base58CheckRepresentation == "edpkuRXPQpuQyDemXE59dyYA1Eu5T94waiiL5PjcWDSkkw86ZvxR2j", keyPair1?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair1?.privateKey.sign(bytes: watermarkedBytes)?.hexString == "d9f272a3ed8459e0b51575dc6660628e64acb231d813f04dc5c2417addd181ddf9da7fe128ed492520c77476d3db3572277b91faabd10b219a4abe6e4f83a900",
				  keyPair1?.privateKey.sign(bytes: watermarkedBytes)?.hexString ?? "-")
		
		let keyPair2 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "", andDerivationPath: "44'/1729'/1'/0'")
		XCTAssert(keyPair2?.privateKey.bytes.hexString == "bf0fc1dc57bd922369cae903710d13f966e49e8e1b0b07b7b727c4653ec5fb14865cd25e1079072c5353fb38723c606701c6e8631522738e59dab732f49b7e23", keyPair2?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair2?.publicKey.bytes.hexString == "865cd25e1079072c5353fb38723c606701c6e8631522738e59dab732f49b7e23", keyPair2?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair2?.publicKey.publicKeyHash == "tz1WCBJKr1rRivyCnN9hREpRAMqrLdmqDcym", keyPair2?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair2?.publicKey.base58CheckRepresentation == "edpkufQ3nNdMJBkgfzCgCLmk1tbfLsqK7W8AR37KiCe7tDVvmsroHh", keyPair2?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair2?.privateKey.sign(bytes: watermarkedBytes)?.hexString == "c1d9165f9b7670bed93abb8a800bdf725b4c63c15de08f17a1d23dd6cdb5dd993e9950efec84a77c573062d82877099e1ce4c22e82982b59412874c3cec8de0a",
				  keyPair2?.privateKey.sign(bytes: watermarkedBytes)?.hexString ?? "-")
		
		let keyPair3 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "", andDerivationPath: "44'/1729'/2147483647'/0'")
		XCTAssert(keyPair3?.privateKey.bytes.hexString == "4a8ef43dfa15c30785231e1ddb2eadd13bfae7297823d42f3cd5352b981d8a993350ae690b1001d12f5b826b5bdc96a8208db3a55e32eb46309385bbf29196ad", keyPair3?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair3?.publicKey.bytes.hexString == "3350ae690b1001d12f5b826b5bdc96a8208db3a55e32eb46309385bbf29196ad", keyPair3?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair3?.publicKey.publicKeyHash == "tz1WKKg7eN7rADsFrfzZmRrEECfBcZbXKtvS", keyPair3?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair3?.publicKey.base58CheckRepresentation == "edpku2piMWnck5esnUbBXeJVK5VppMjxN85oEuPyynPqrmtC34FuKT", keyPair3?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair3?.privateKey.sign(bytes: watermarkedBytes)?.hexString == "cc9e7d3bff6a17c8f3a6385397fb0d4e3136742e7e78f4719e7971223b3633a23c73a98d2a143d3693f480d93776506b38a9a8ec571e289b1e75b0a4bd26b200",
				  keyPair3?.privateKey.sign(bytes: watermarkedBytes)?.hexString ?? "-")
		
		let keyPair4 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "", andDerivationPath: "44'/1729'/1'/1'/1'")
		XCTAssert(keyPair4?.privateKey.bytes.hexString == "bf7a753dde1af40df5ecc9b4f0d6471843d4c0c904f3bc8ecf627402bffdc03506b716cdb9ea32ef268de284fed61434195bc86c7d5ceb3f116ce794d6975319", keyPair4?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair4?.publicKey.bytes.hexString == "06b716cdb9ea32ef268de284fed61434195bc86c7d5ceb3f116ce794d6975319", keyPair4?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair4?.publicKey.publicKeyHash == "tz1dAgezeiGexQkgfbPm8MgP1XTqA4rJRt3C", keyPair4?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair4?.publicKey.base58CheckRepresentation == "edpkthBU4kJTd8rdbeUt3MafV4KHQEMoJ9M5idVtBrCVm5vBE2kY8K", keyPair4?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair4?.privateKey.sign(bytes: watermarkedBytes)?.hexString == "f98074f0fc2e34b09d6ca973be900ef698718a323db5d55eb6a9633fc07659f8fcb1a22d11453ead8e36fe866de4adcbdb35be241b2828f21146f369184ced0e",
				  keyPair4?.privateKey.sign(bytes: watermarkedBytes)?.hexString ?? "-")
		
		let keyPair5 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "superSecurePassphrase", andDerivationPath: "44'/1729'/0'/0'")
		XCTAssert(keyPair5?.privateKey.bytes.hexString == "ebea8d3287af11f7ab844288baaddccef75ba8a862520eca180727ece2228a3115e40e65b90e549f1f8eee368bb47d12ffdbad8322004e47c7e9a2393b4d94e3", keyPair5?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair5?.publicKey.bytes.hexString == "15e40e65b90e549f1f8eee368bb47d12ffdbad8322004e47c7e9a2393b4d94e3", keyPair5?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair5?.publicKey.publicKeyHash == "tz1TmVDbFH63shXAzmmbDkYRH3nz1RSLV463", keyPair5?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair5?.publicKey.base58CheckRepresentation == "edpktos7HPEb8SYPeZAiRQ2e96zxe12PaSiMsBxZVr12Bvi8uCEyUm", keyPair5?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair5?.privateKey.sign(bytes: watermarkedBytes)?.hexString == "45825aeb7e4cb6515d783312e527d4932029fceae883f8a0cfde5c4b938f5412a1ae86413d7b2dff41fb243cefdd4cb08cc9665968acb185e305ac1ca6ca8d0b",
				  keyPair5?.privateKey.sign(bytes: watermarkedBytes)?.hexString ?? "-")
	}
	
	func testEllipticalCurve() {
		XCTAssert(EllipticalCurve.fromAddress("TZ1abc123") == .ed25519)
		XCTAssert(EllipticalCurve.fromAddress("TZ2abc123") == .secp256k1)
		XCTAssert(EllipticalCurve.fromAddress("tz1abc123") == .ed25519)
		XCTAssert(EllipticalCurve.fromAddress("tz2abc123") == .secp256k1)
		XCTAssert(EllipticalCurve.fromAddress("tZ1abc123") == .ed25519)
		XCTAssert(EllipticalCurve.fromAddress("tZ2abc123") == .secp256k1)
	}
}
