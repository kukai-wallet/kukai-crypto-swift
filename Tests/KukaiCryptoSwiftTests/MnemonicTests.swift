//
//  MnemonicTests.swift
//  
//
//  Created by Simon Mcloughlin on 09/06/2022.
//

import XCTest
@testable import KukaiCryptoSwift

final class MnemonicTests: XCTestCase {
	
	func testWords() throws {
		let mnemonic = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform")
		
		let seed1 = try mnemonic.seed()
		XCTAssert(seed1.hexString == "80d4e52897c8e14fbfad4637373de405fa2cc7f27eb9f890db975948b0e7fdb0e7540cb3d355291669353a5a261350ac8b8978d6640d388de8a293adcf020b8d", seed1.hexString)
		
		let seed2 = try mnemonic.seed(passphrase: "aPassword")
		XCTAssert(seed2.hexString == "e469380003a26cae690330efddb4f9edfb389ea1d35576324f2a91b5f0e91105e1f9a8cde26f736d45e12547019cb5fd60c92c5353e59d759f40b43a4e06c22c", seed2.hexString)
	}
	
	func testNumberOfWords() throws {
		let mnemonic = try Mnemonic(numberOfWords: .twentyFour)
		XCTAssert(mnemonic.words.count == 24)
	}
	
	func testEntropy() throws {
		let mnemonic = try Mnemonic(entropy: Int.strongest)
		XCTAssert(mnemonic.words.count == 24)
	}
}
