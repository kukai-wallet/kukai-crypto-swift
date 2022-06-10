//
//  MnemonicTests.swift
//  
//
//  Created by Simon Mcloughlin on 09/06/2022.
//

import XCTest
@testable import KukaiCryptoSwift

final class MnemonicTests: XCTestCase {
	
	func testExample() throws {
		/*
		let mnemonic = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform")
		let seed = try mnemonic.seed(passphrase: "").hexString
		let shortenedSeed = String(seed[..<seed.index(seed.startIndex, offsetBy: 64)])
		
		if let priKey = PrivateKey(seedString: shortenedSeed, signingCurve: .ed25519) {
			let pubKey = PublicKey(privateKey: priKey)
			let hash = pubKey?.publicKeyHash ?? "-"
			XCTAssert(hash == "tz1T3QZ5w4K11RS3vy4TXiZepraV9R5GzsxG", hash)
			
			
		} else {
			XCTFail()
		}
		
		
		
		if let priKey = PrivateKey(seedString: shortenedSeed, signingCurve: .secp256k1) {
			let pubKey = PublicKey(privateKey: priKey)
			let hash = pubKey?.publicKeyHash ?? "-"
			XCTAssert(hash == "tz2UiZQJwaVAKxRuYxV8Tx5k8a64gZx1ZwYJ", hash)
			
			
		} else {
			XCTFail()
		}
		*/
		
		
		/*
		let pairTz1 = KeyPair.from(seedString: shortenedSeed, signingCurve: .ed25519)
		let pairTz2 = KeyPair.from(seedString: shortenedSeed, signingCurve: .secp256k1)
		
		
		XCTAssert(pairTz1?.publicKey.publicKeyHash == "tz1T3QZ5w4K11RS3vy4TXiZepraV9R5GzsxG", pairTz1?.publicKey.publicKeyHash ?? "-")
		XCTAssert(pairTz2?.publicKey.publicKeyHash == "tz2UiZQJwaVAKxRuYxV8Tx5k8a64gZx1ZwYJ", pairTz2?.publicKey.publicKeyHash ?? "-")
		
		print("pairTz1.privateKey: \(pairTz1?.privateKey.bytes.hexString)")
		print("pairTz1.publicKey: \(pairTz1?.publicKey.bytes.hexString)")
		print("pairTz1.publicKey.publicKeyHash: \(pairTz1?.publicKey.publicKeyHash)")
		print("pairTz2.privateKey: \(pairTz2?.privateKey.bytes.hexString)")
		print("pairTz2.publicKey: \(pairTz2?.publicKey.bytes.hexString)")
		print("pairTz2.publicKey.publicKeyHash: \(pairTz2?.publicKey.publicKeyHash)")
		*/
	}
	
	func testAnotherExample() throws {
		
		/*
		let mnemonic = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform")
		let seed = try mnemonic.seed(passphrase: "").hexString
		
		let keyPair = try HD.seedToKeyPair(Data(hexString: seed), derivationPath: HD.defaultDerivationPath)
		
		
		print("\n\n\n")
		print("Private key: \(keyPair.privateKey.bytes.hexString)")
		print("Public key: \(keyPair.publicKey.bytes.hexString)")
		print("Address: \(keyPair.publicKey.publicKeyHash ?? "-")")
		print("\n\n\n")
		*/
		
		
		
		let mnemonic = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform")
		let seed = try mnemonic.seed(passphrase: "").hexString
		
		let keyPair = KeyPair.hd(fromSeedString: seed)
		
		XCTAssert(keyPair?.publicKey.publicKeyHash == "tz1bQnUB6wv77AAnvvkX5rXwzKHis6RxVnyF", keyPair?.publicKey.publicKeyHash ?? "-")
	}
}
