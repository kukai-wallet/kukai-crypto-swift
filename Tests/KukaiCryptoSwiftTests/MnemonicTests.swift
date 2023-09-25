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
		let mnemonic12 = try Mnemonic(numberOfWords: .twelve)
		XCTAssert(mnemonic12.words.count == 12)
		
		let mnemonic15 = try Mnemonic(numberOfWords: .fifteen)
		XCTAssert(mnemonic15.words.count == 15)
		
		let mnemonic18 = try Mnemonic(numberOfWords: .eighteen)
		XCTAssert(mnemonic18.words.count == 18)
		
		let mnemonic21 = try Mnemonic(numberOfWords: .twentyOne)
		XCTAssert(mnemonic21.words.count == 21)
		
		let mnemonic24 = try Mnemonic(numberOfWords: .twentyFour)
		XCTAssert(mnemonic24.words.count == 24)
	}
	
	func testChinese() throws {
		let mnemonic24 = try Mnemonic(numberOfWords: .twentyFour, in: .chinese)
		XCTAssert(mnemonic24.words.count == 24)
		
		let firstWord = mnemonic24.words.first ?? ""
		let containedInEnglish = WordList.english.words.contains(firstWord)
		let containedInChinese = WordList.chinese.words.contains(firstWord)
		
		XCTAssert(!containedInEnglish)
		XCTAssert(containedInChinese)
	}
	
	func testEntropy() throws {
		let mnemonic1 = try Mnemonic(entropy: Int.strongest)
		XCTAssert(mnemonic1.words.count == 24)
		
		let mnemonic2 = try Mnemonic(entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")
		XCTAssert(mnemonic2.words.count == 12)
	}
	
	func testValid() throws {
		let mnemonic1 = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform")
		XCTAssert(mnemonic1.isValid() == true)
		
		let mnemonic2 = try? Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten")
		XCTAssert(mnemonic2 == nil)
		
		let mnemonic3 = try Mnemonic(seedPhrase: "remember smile trip asshole era cube worry fuel bracket eight kitten inform")
		XCTAssert(mnemonic3.isValid() == false)
		
		let mnemonic4 = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform remember smile trip tumble era cube worry fuel bracket eight kitten inform")
		XCTAssert(mnemonic4.isValid() == false)
		
		let mnemonic5 = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten inform remember smile trip tumble era cube worry fuel bracket eight kitten infomr")
		XCTAssert(mnemonic5.isValid() == false)
		
		let mnemonic6 = try Mnemonic(seedPhrase: "tell me more about your awesome but totally invalid mnemonic word1 word2")
		XCTAssert(mnemonic6.isValid() == false)
		
		let mnemonic7 = try Mnemonic(seedPhrase: "remember smile trip tumble era cube worry fuel bracket eight kitten remember")
		XCTAssert(mnemonic7.isValid() == false)
	}
}
