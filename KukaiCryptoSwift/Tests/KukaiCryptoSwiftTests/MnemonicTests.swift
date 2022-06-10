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
	}
	
	func testAnotherExample() throws {
		
		let mnemonic = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform")
		let seed = try mnemonic.seed(passphrase: "").hexString
		
		let keyPair = try HD.seedToKeyPair(Data(hexString: seed), derivationPath: HD.defaultDerivationPath)
		
		
		print("\n\n\n")
		print("Private key: \(keyPair.privateKey.bytes.hexString)")
		print("Public key: \(keyPair.publicKey.bytes.hexString)")
		print("Address: \(keyPair.publicKey.publicKeyHash ?? "-")")
		print("\n\n\n")
	}
}
