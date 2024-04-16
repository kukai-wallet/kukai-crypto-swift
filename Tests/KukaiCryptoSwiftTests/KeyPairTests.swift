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
		let mnemonic = try Mnemonic(seedPhrase: "kit trigger pledge excess payment sentence dutch mandate start sense seed venture")
		
		let keyPair1 = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "")
		let signature1 = keyPair1?.privateKey.sign(bytes: watermarkedBytes) ?? []
		let signatureHex1 = signature1.hexString
		XCTAssert(keyPair1?.privateKey.bytes.hexString == "7d85c254fa624f29ae54e981295594212cba5767ebd5f763851d97c55b6a88d65c4da5f73069ef888317361cc035736716683a6bbf417336f1988bd78756e93f", keyPair1?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair1?.publicKey.bytes.hexString == "5c4da5f73069ef888317361cc035736716683a6bbf417336f1988bd78756e93f", keyPair1?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair1?.publicKey.publicKeyHash == "tz1Xx4vxaUCkgxfaUhr1EV1kvTE2Rt3BkEdm", keyPair1?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair1?.publicKey.base58CheckRepresentation == "edpkuLshcvrn2x7c2QtCCMv8XFNEM2gHkPDGb3paKt2hBvnBRfepR4", keyPair1?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair1?.privateKey.base58CheckRepresentation == "edskRtSFLebJzJif7KX55PMEquDPvYybzRCug2oUfvExABrZKjEdcso2bDGnu2SM47BbWAxsTMsNWCQarrezUWzMjxUxbZLFjn", keyPair1?.privateKey.base58CheckRepresentation ?? "-")
		XCTAssert(signatureHex1 == "a48c9404671f257f4aa088dad8862a4a39ada8ee88f223e98f67892fc9964c3026be89dbdd57e4a6800dda78f303eba7e5ce19cf3d6934435471682961dcaf0c", signatureHex1)
		XCTAssert(keyPair1?.publicKey.verify(message: watermarkedBytes, signature: signature1) == true)
		
		let keyPair2 = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "superSecurePassphrase")
		let signature2 = keyPair2?.privateKey.sign(bytes: watermarkedBytes) ?? []
		let signatureHex2 = signature2.hexString
		XCTAssert(keyPair2?.privateKey.bytes.hexString == "02484d505196451ebbbde85c4ee3d2089219b51c1767798e4eb63cc9bfb5e62b7b31e1abbe67284d92fc523302f39e46611850e5d3c22d37b577dfcd464cb72d", keyPair2?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair2?.publicKey.bytes.hexString == "7b31e1abbe67284d92fc523302f39e46611850e5d3c22d37b577dfcd464cb72d", keyPair2?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair2?.publicKey.publicKeyHash == "tz1ZYoRJ2iouRi5r6CT83Ptp9Bof7RMRkxXe", keyPair2?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair2?.publicKey.base58CheckRepresentation == "edpkuaUnRZQzwP1QYHFFXzbhN919wg17KHm7vHH86pxxgSSkqT7U4a", keyPair2?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair2?.privateKey.base58CheckRepresentation == "edskRcK6XU6Bhvjic9daFwgXH3DchwNNDzJCHjvCpB3PKvXdu3dPdBnf5nk1WrSt5zaZiXyrAsLqrgDvGKeP7F7GkZRZTmwo78", keyPair2?.privateKey.base58CheckRepresentation ?? "-")
		XCTAssert(signatureHex2 == "07d0220bd7bb5b0dff17fb1c26f9e171bc836fe4a90f72646c11a5228e0d25fb4b61b40e0145476c2be2c6220cf8f204a1b9f7d6ba2b6ea77dfa6edd17a66a08", signatureHex2)
		XCTAssert(keyPair2?.publicKey.verify(message: watermarkedBytes, signature: signature2) == true)
	}
	
	func testRegularTZ2() throws {
		let messageToSign = "something very interesting that needs to be signed".bytes
		let watermarkedBytes = messageToSign.addOperationWatermarkAndHash() ?? []
		
		let privetKeyBytes: [UInt8] = [125, 133, 194, 84, 250, 98, 79, 41, 174, 84, 233, 129, 41, 85, 148, 33, 44, 186, 87, 103, 235, 213, 247, 99, 133, 29, 151, 197, 91, 106, 136, 214]
		let base58encodedKey = Base58Check.encode(message: privetKeyBytes, prefix: Prefix.Keys.Secp256k1.secret)
		
		if let privateKey = PrivateKey(base58encodedKey, signingCurve: .secp256k1), let pubKey = KeyPair.secp256k1PublicKey(fromPrivateKeyBytes: privateKey.bytes) {
			let tempAddress = pubKey.publicKeyHash
			
			let signature = privateKey.sign(bytes: watermarkedBytes) ?? []
			let signatureHex = signature.hexString
			
			XCTAssert(tempAddress == "tz2HpbGQcmU3UyusJ78Sbqeg9fYteamSMDGo", tempAddress ?? "-")
			XCTAssert(signatureHex == "2c9f14f18a21867fd2fe3130ad3aaeca7cb1c9421d78d32537173b98b25ed07d054837a878c7e9fe2d237b42c90e5aa2a63a58774833221707cc303a2121b3e7", signatureHex)
			
		} else {
			XCTFail("Failed to create private key or public key")
		}
	}
	
	func testHD() throws {
		let messageToSign = "something very interesting that needs to be signed".bytes
		let watermarkedBytes = messageToSign.addOperationWatermarkAndHash() ?? []
		let mnemonic = try Mnemonic(seedPhrase: "gym exact clown can answer hope sample mirror knife twenty powder super imitate lion churn almost shed chalk dust civil gadget pyramid helmet trade")
		
		let keyPair1 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "", andDerivationPath: "44'/1729'/0'/0'")
		let signature1 = keyPair1?.privateKey.sign(bytes: watermarkedBytes) ?? []
		let signatureHex1 = signature1.hexString
		XCTAssert(keyPair1?.privateKey.bytes.hexString == "7b0c9fc748c9c784d50152fd2db370522a8727a8ec68fd0b7ef456330e2e089c66dc7517defa76d4355280505068b59172a568cacbd46c1f5f91a247c29426bc", keyPair1?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair1?.publicKey.bytes.hexString == "66dc7517defa76d4355280505068b59172a568cacbd46c1f5f91a247c29426bc", keyPair1?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair1?.publicKey.publicKeyHash == "tz1TyyX7U6r6tB1uSS4aUnfKX9rj3y9NCEVL", keyPair1?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair1?.publicKey.base58CheckRepresentation == "edpkuRXPQpuQyDemXE59dyYA1Eu5T94waiiL5PjcWDSkkw86ZvxR2j", keyPair1?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair1?.privateKey.base58CheckRepresentation == "edskRt7UsfGdfmmruGVV1GY2YFHpxTDeML8ZLwSHihw6RLaXNTAEiFRaooAMCFL3BDAT5ATN5cHswXm3HKu6rsJUmF2U3n4t1z", keyPair1?.privateKey.base58CheckRepresentation ?? "-")
		XCTAssert(signatureHex1 == "d9f272a3ed8459e0b51575dc6660628e64acb231d813f04dc5c2417addd181ddf9da7fe128ed492520c77476d3db3572277b91faabd10b219a4abe6e4f83a900", signatureHex1)
		XCTAssert(keyPair1?.publicKey.verify(message: watermarkedBytes, signature: signature1) == true)
		
		let keyPair2 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "", andDerivationPath: "44'/1729'/1'/0'")
		let signature2 = keyPair2?.privateKey.sign(bytes: watermarkedBytes) ?? []
		let signatureHex2 = signature2.hexString
		XCTAssert(keyPair2?.privateKey.bytes.hexString == "bf0fc1dc57bd922369cae903710d13f966e49e8e1b0b07b7b727c4653ec5fb14865cd25e1079072c5353fb38723c606701c6e8631522738e59dab732f49b7e23", keyPair2?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair2?.publicKey.bytes.hexString == "865cd25e1079072c5353fb38723c606701c6e8631522738e59dab732f49b7e23", keyPair2?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair2?.publicKey.publicKeyHash == "tz1WCBJKr1rRivyCnN9hREpRAMqrLdmqDcym", keyPair2?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair2?.publicKey.base58CheckRepresentation == "edpkufQ3nNdMJBkgfzCgCLmk1tbfLsqK7W8AR37KiCe7tDVvmsroHh", keyPair2?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair2?.privateKey.base58CheckRepresentation == "edskS31ZXzfzGBi1jEigpPvaWwVzwWCX3PNhx8FUpwY65SZC2oVmZ4iCHqwXCC6LBiGgdknhzJ6xAzHbpwQMEH3KKVjZ4aL4kw", keyPair2?.privateKey.base58CheckRepresentation ?? "-")
		XCTAssert(signatureHex2 == "c1d9165f9b7670bed93abb8a800bdf725b4c63c15de08f17a1d23dd6cdb5dd993e9950efec84a77c573062d82877099e1ce4c22e82982b59412874c3cec8de0a", signatureHex2)
		XCTAssert(keyPair2?.publicKey.verify(message: watermarkedBytes, signature: signature2) == true)
		
		let keyPair3 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "", andDerivationPath: "44'/1729'/2147483647'/0'")
		let signature3 = keyPair3?.privateKey.sign(bytes: watermarkedBytes) ?? []
		let signatureHex3 = signature3.hexString
		XCTAssert(keyPair3?.privateKey.bytes.hexString == "4a8ef43dfa15c30785231e1ddb2eadd13bfae7297823d42f3cd5352b981d8a993350ae690b1001d12f5b826b5bdc96a8208db3a55e32eb46309385bbf29196ad", keyPair3?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair3?.publicKey.bytes.hexString == "3350ae690b1001d12f5b826b5bdc96a8208db3a55e32eb46309385bbf29196ad", keyPair3?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair3?.publicKey.publicKeyHash == "tz1WKKg7eN7rADsFrfzZmRrEECfBcZbXKtvS", keyPair3?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair3?.publicKey.base58CheckRepresentation == "edpku2piMWnck5esnUbBXeJVK5VppMjxN85oEuPyynPqrmtC34FuKT", keyPair3?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair3?.privateKey.base58CheckRepresentation == "edskRmmXh3vqPYi3k2eVZRShEnA6u6QcYVM4iUqVw1ASxLyF58Chk5wd4MPwLSPsSALVDM8DsRCjpWtuMFzNqVTHUU8r5E8Cjx", keyPair3?.privateKey.base58CheckRepresentation ?? "-")
		XCTAssert(signatureHex3 == "cc9e7d3bff6a17c8f3a6385397fb0d4e3136742e7e78f4719e7971223b3633a23c73a98d2a143d3693f480d93776506b38a9a8ec571e289b1e75b0a4bd26b200", signatureHex3)
		XCTAssert(keyPair3?.publicKey.verify(message: watermarkedBytes, signature: signature3) == true)
		
		let keyPair4 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "", andDerivationPath: "44'/1729'/1'/1'/1'")
		let signature4 = keyPair4?.privateKey.sign(bytes: watermarkedBytes) ?? []
		let signatureHex4 = signature4.hexString
		XCTAssert(keyPair4?.privateKey.bytes.hexString == "bf7a753dde1af40df5ecc9b4f0d6471843d4c0c904f3bc8ecf627402bffdc03506b716cdb9ea32ef268de284fed61434195bc86c7d5ceb3f116ce794d6975319", keyPair4?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair4?.publicKey.bytes.hexString == "06b716cdb9ea32ef268de284fed61434195bc86c7d5ceb3f116ce794d6975319", keyPair4?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair4?.publicKey.publicKeyHash == "tz1dAgezeiGexQkgfbPm8MgP1XTqA4rJRt3C", keyPair4?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair4?.publicKey.base58CheckRepresentation == "edpkthBU4kJTd8rdbeUt3MafV4KHQEMoJ9M5idVtBrCVm5vBE2kY8K", keyPair4?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair4?.privateKey.base58CheckRepresentation == "edskS34iyJpTAPGiAXmAsuraxJeujUbmqssGagUf1mZGBuoeJiXtCiBqEx4k22BPHmT5nSaY2tPucSa161Lzqi2fgt8pYqkvJQ", keyPair4?.privateKey.base58CheckRepresentation ?? "-")
		XCTAssert(signatureHex4 == "f98074f0fc2e34b09d6ca973be900ef698718a323db5d55eb6a9633fc07659f8fcb1a22d11453ead8e36fe866de4adcbdb35be241b2828f21146f369184ced0e", signatureHex4)
		XCTAssert(keyPair4?.publicKey.verify(message: watermarkedBytes, signature: signature4) == true)
		
		let keyPair5 = KeyPair.hd(fromMnemonic: mnemonic, passphrase: "superSecurePassphrase", andDerivationPath: "44'/1729'/0'/0'")
		let signature5 = keyPair5?.privateKey.sign(bytes: watermarkedBytes) ?? []
		let signatureHex5 = signature5.hexString
		XCTAssert(keyPair5?.privateKey.bytes.hexString == "ebea8d3287af11f7ab844288baaddccef75ba8a862520eca180727ece2228a3115e40e65b90e549f1f8eee368bb47d12ffdbad8322004e47c7e9a2393b4d94e3", keyPair5?.privateKey.bytes.hexString ?? "-")
		XCTAssert(keyPair5?.publicKey.bytes.hexString == "15e40e65b90e549f1f8eee368bb47d12ffdbad8322004e47c7e9a2393b4d94e3", keyPair5?.publicKey.bytes.hexString ?? "-")
		XCTAssert(keyPair5?.publicKey.publicKeyHash == "tz1TmVDbFH63shXAzmmbDkYRH3nz1RSLV463", keyPair5?.publicKey.publicKeyHash ?? "-")
		XCTAssert(keyPair5?.publicKey.base58CheckRepresentation == "edpktos7HPEb8SYPeZAiRQ2e96zxe12PaSiMsBxZVr12Bvi8uCEyUm", keyPair5?.publicKey.base58CheckRepresentation ?? "-")
		XCTAssert(keyPair5?.privateKey.base58CheckRepresentation == "edskS8svPN21gfV4fhRYirkN5LY28VoFDnsUMuisWDq2PCnsydAdeQuYiRAmhxquV2mqZBiadJCVzB8tYVycWbjpUkiN9XXGGy", keyPair5?.privateKey.base58CheckRepresentation ?? "-")
		XCTAssert(signatureHex5 == "45825aeb7e4cb6515d783312e527d4932029fceae883f8a0cfde5c4b938f5412a1ae86413d7b2dff41fb243cefdd4cb08cc9665968acb185e305ac1ca6ca8d0b", signatureHex5)
		XCTAssert(keyPair5?.publicKey.verify(message: watermarkedBytes, signature: signature5) == true)
	}
	
	func testEllipticalCurve() {
		XCTAssert(EllipticalCurve.fromAddress("TZ1abc123") == .ed25519)
		XCTAssert(EllipticalCurve.fromAddress("TZ2abc123") == .secp256k1)
		XCTAssert(EllipticalCurve.fromAddress("tz1abc123") == .ed25519)
		XCTAssert(EllipticalCurve.fromAddress("tz2abc123") == .secp256k1)
		XCTAssert(EllipticalCurve.fromAddress("tZ1abc123") == .ed25519)
		XCTAssert(EllipticalCurve.fromAddress("tZ2abc123") == .secp256k1)
		
		XCTAssert(EllipticalCurve.fromAddress("tz3abc123") == nil)
		XCTAssert(EllipticalCurve.fromAddress("tz4abc123") == nil)
		XCTAssert(EllipticalCurve.fromAddress("kt1abc123") == nil)
	}
	
	func testUncompress() throws {
		let mnemonic = try Mnemonic(seedPhrase: "gym exact clown can answer hope sample mirror knife twenty powder super imitate lion churn almost shed chalk dust civil gadget pyramid helmet trade")
		let keyPair1 = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "")
		
		let uncompressed1 = KeyPair.secp256k1PublicKey_uncompressed(fromBytes: keyPair1?.publicKey.bytes ?? [])
		let data1 = Data(bytes: uncompressed1, count: uncompressed1.count)
		let dataString1 = data1.hexString
		
		XCTAssert(dataString1.count == 0, dataString1.count.description)
		XCTAssert(dataString1 == "", dataString1)
	}
	
	func testSafetyChecks() throws {
		let messageToSign = "something very interesting that needs to be signed".bytes
		let watermarkedBytes = messageToSign.addOperationWatermarkAndHash() ?? []
		let mnemonic = try Mnemonic(seedPhrase: "kit trigger pledge excess payment sentence dutch mandate start sense seed venture")
		
		let keyPair1 = KeyPair.regular(fromMnemonic: mnemonic, passphrase: "")
		var signatureBytes = keyPair1?.privateKey.sign(bytes: watermarkedBytes) ?? []
		signatureBytes.append(contentsOf: signatureBytes)
		let signature1 = signatureBytes
		
		// Test function doesn't crash with more than 64 byte signature
		XCTAssert(signatureBytes.count > 64)
		XCTAssert(keyPair1?.publicKey.verify(message: watermarkedBytes, signature: signature1) == true)
		
		// Test doesn't crash with empty
		XCTAssert(keyPair1?.publicKey.verify(message: [], signature: []) == false)
		
		
		
		let uncompressed1 = KeyPair.secp256k1PublicKey_uncompressed(fromBytes: signatureBytes)
		let data1 = Data(bytes: uncompressed1, count: uncompressed1.count)
		let dataString1 = data1.hexString
		
		XCTAssert(dataString1.count == 0, dataString1.count.description)
		XCTAssert(dataString1 == "", dataString1)
		
		
		let pubKeySafety = KeyPair.secp256k1PublicKey(fromPrivateKeyBytes: signatureBytes)
		XCTAssert(pubKeySafety == nil, (pubKeySafety?.bytes.count ?? 0).description)
	}
}
