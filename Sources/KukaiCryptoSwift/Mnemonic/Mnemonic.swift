
// From: https://github.com/KevinVitale/WalletKit

import Foundation
import CommonCrypto
import CryptoKit

public enum MnemonicError: Swift.Error {
	case seedDerivationFailed
	case seedPhraseInvalid(String)
	case error(Swift.Error)
}

/**
 * A list of words which can generate a private key.
 */
public struct Mnemonic: Equatable, Codable {
	
	/// Helper enum used to choose the number of words for a mnemonic
	public enum NumberOfWords: Int {
		case twelve = 128
		case fifteen = 160
		case eighteen = 192
		case twentyOne = 224
		case twentyFour = 256
	}
	
	/// The list of words as a single sentence.
	public var phrase: String = ""
	
	/// The list of words.
	public var words: [String] {
		phrase.split(separator: " ").map(String.init)
	}
	
	/**
	 * Create a mnemonic from a list of `words`.
	 *
	 * - parameter words: An array of words.
	 */
	fileprivate init<Words: Collection>(words: Words) throws where Words.Element: StringProtocol {
		guard Int.wordCounts.contains(words.count) else {
			throw MnemonicError.seedPhraseInvalid(words.joined(separator: " "))
		}
		self.phrase = words.joined(separator: " ")
	}
	
	public init(seedPhrase phrase: String?) throws {
		if let phrase = phrase {
			try self.init(words: phrase.split(separator: " "))
		}
		else {
			try self.init()
		}
	}
	
	public init(strength: Int = .strongest, in vocabulary: WordList = .english) throws {
		try self.init(entropy: strength, in: vocabulary)
	}
	
	public init(numberOfWords: NumberOfWords, in vocabulary: WordList = .english) throws {
		try self.init(entropy: numberOfWords.rawValue, in: vocabulary)
	}
	
	
	/**
	 * Create a mnemonic from a pre-computed `entropy`, with phrase_ pulled from
	 * the `vocabulary` list.
	 *
	 * - parameter entropy
	 * - parameter vocabulary
	 */
	public init<Entropy: EntropyGenerator>(entropy: Entropy, in vocabulary: WordList = .english) throws {
		self = try Mnemonic(words: try vocabulary.randomWords(withEntropy: entropy))
	}
	
	/**
	 * Create the mnemonic's private key (seed).
	 *
	 * - warning: Calling this function can take some time. Avoid calling
	 *            this function from the main thread, when possible.
	 *
	 * **BIP39**:
	 *
	 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
	 *
	 * - parameter passphrase: Associates a secret (for extra security).
	 *
	 * - returns: A _result_ with the seed's bytes, or an `Error`.
	 */
	public func seed(passphrase: String = "") throws -> Data {
		guard var passwordData = self.phrase.data(using: .utf8)?.map(Int8.init) else {
			throw MnemonicError.seedPhraseInvalid("Can't convert to data")
		}
		
		let salt = ("mnemonic" + passphrase)
		let passwordCount = self.phrase.count
		
		var saltData = salt.bytes
		let saltCount = salt.count
		
		var data = [UInt8](repeating: 0, count: 64)
		
		let status = CCKeyDerivationPBKDF( CCPBKDFAlgorithm(kCCPBKDF2),
										   &passwordData, passwordCount,
										   &saltData, saltCount,
										   CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512),
										   2048,
										   &data,
										   data.count)
		
		guard status == kCCSuccess else {
			throw MnemonicError.seedDerivationFailed
		}
		
		return Data(data)
	}
	
	/**
	 Scrub the phrase from memory by replacing with 0's
	 */
	public mutating func scrub() {
		phrase = String(repeating: "0", count: phrase.count)
	}
	
	/**
	 Derive the checksum portion of an array of bits
	 */
	public static func deriveChecksumBits(_ bytes: [UInt8]) -> String {
		let ENT = bytes.count * 8;
		let CS = ENT / 32
		
		let hash = SHA256.hash(data: bytes)
		let hashbits = String(hash.flatMap { ("00000000" + String($0, radix:2)).suffix(8) })
		return String(hashbits.prefix(CS))
	}
	
	/**
	 Verify the chechsum of the supplied words to esnure its a valid phrase
	 */
	public static func isValidChecksum(phrase: [String], wordlist: WordList = WordList.english) -> Bool {
		let wordL = wordlist.words
		var bits = ""
		for word in phrase {
			guard let i = wordL.firstIndex(of: word) else { return false }
			bits += ("00000000000" + String(i, radix: 2)).suffix(11)
		}
		
		let dividerIndex = bits.count / 33 * 32
		let entropyBits = String(bits.prefix(dividerIndex))
		let checksumBits = String(bits.suffix(bits.count - dividerIndex))
		
		guard let regex = try? NSRegularExpression(pattern: "[01]{1,8}", options: .caseInsensitive) else {
			return false
		}
		
		let entropyBytes = regex.matches(in: entropyBits, options: [], range: NSRange(location: 0, length: entropyBits.count)).map {
			UInt8(strtoul(String(entropyBits[Range($0.range, in: entropyBits)!]), nil, 2))
		}
		
		return checksumBits == deriveChecksumBits(entropyBytes)
	}
	
	/**
	 Check a mnemonic is of the correct length, and is made up of valid BIP39 words
	 */
	public func isValid(in vocabulary: WordList = .english) -> Bool {
		let words = self.words
		
		if words.count != 12 && words.count != 15 && words.count != 18 && words.count != 21 && words.count != 24 {
			return false
		}
		
		let wordList = vocabulary.words
		
		for word in words {
			guard wordList.firstIndex(of: word) != nil else {
				return false
			}
		}
		
		return Mnemonic.isValidChecksum(phrase: words, wordlist: vocabulary)
	}
}
