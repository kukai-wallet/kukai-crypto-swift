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
		let mnemonic = try Mnemonic(seedPhrase: "kit trigger pledge excess payment sentence dutch mandate start sense seed venture")
		
		let seed1 = try mnemonic.seed()
		XCTAssert(seed1.hexString == "7d85c254fa624f29ae54e981295594212cba5767ebd5f763851d97c55b6a88d6ebf09bf313d6d0efad8d2f30e4cba84a40aa01e20c4abd58003f9c021d0cb0e8", seed1.hexString)
		
		let seed2 = try mnemonic.seed(passphrase: "aPassword")
		XCTAssert(seed2.hexString == "e2397068b1e5de3bb09cedec6ff52a636a09931b30097e9b3663f2dbcd93acd38a967cd7dc997557f79b407aacf3bbdb038e0188498a81ae38cd660a6f44f95b", seed2.hexString)
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
		let mnemonic1 = try Mnemonic(seedPhrase: "kit trigger pledge excess payment sentence dutch mandate start sense seed venture")
		XCTAssert(mnemonic1.isValid() == true)
		
		let mnemonic2 = try? Mnemonic(seedPhrase: "kit trigger pledge excess payment sentence dutch mandate start sense seed")
		XCTAssert(mnemonic2 == nil)
		
		let mnemonic3 = try Mnemonic(seedPhrase: "kit trigger pledge asshole payment sentence dutch mandate start sense seed venture")
		XCTAssert(mnemonic3.isValid() == false)
		
		let mnemonic4 = try Mnemonic(seedPhrase: "kit trigger pledge excess payment sentence dutch mandate start sense seed venture kit trigger pledge excess payment sentence dutch mandate start sense seed venture")
		XCTAssert(mnemonic4.isValid() == false)
		
		let mnemonic5 = try Mnemonic(seedPhrase: "kit trigger pledge excess payment sentence dutch mandate start sense seed venture kit trigger pledge excess payment sentence dutch mandate start sense seed ventrue")
		XCTAssert(mnemonic5.isValid() == false)
		
		let mnemonic6 = try Mnemonic(seedPhrase: "tell me more about your awesome but totally invalid mnemonic word1 word2")
		XCTAssert(mnemonic6.isValid() == false)
		
		let mnemonic7 = try Mnemonic(seedPhrase: "kit trigger pledge excess payment sentence dutch mandate start sense seed kit")
		XCTAssert(mnemonic7.isValid() == false)
		
		let mnemonic8 = try Mnemonic(seedPhrase: "Kit trigger pledge excess payment sentence dutch mandate start sense seed venture")
		XCTAssert(mnemonic8.isValid() == false)
	}
}
