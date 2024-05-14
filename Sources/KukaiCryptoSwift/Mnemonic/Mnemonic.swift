
// From: https://github.com/KevinVitale/WalletKit

import Foundation
import CommonCrypto
import CryptoKit

public enum MnemonicError: Swift.Error {
	case seedDerivationFailed
	case seedPhraseInvalid(String)
	case error(Swift.Error)
	case invalidWordCount
	case invalidWordToShift
	case invalidMnemonic
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
	
	/**
	 Modifed from: https://github.com/pengpengliu/BIP39/blob/master/Sources/BIP39/Mnemonic.swift
	 Convert the current Mnemonic back into entropy
	 */
	public func toEntropy(ignoreChecksum: Bool, wordlist: WordList = WordList.english) throws -> [UInt8] {
		let wordListWords = wordlist.words
		
		let bits = try words.map { (word) -> String in
			guard let index = wordListWords.firstIndex(of: word) else {
				throw MnemonicError.invalidMnemonic
			}
			
			var str = String(index, radix:2)
			while str.count < 11 {
				str = "0" + str
			}
			return str
		}.joined(separator: "")
		
		let dividerIndex = Int(Double(bits.count / 33).rounded(.down) * 32)
		let entropyBits = String(bits.prefix(dividerIndex))
		let checksumBits = String(bits.suffix(bits.count - dividerIndex))
		
		let regex = try! NSRegularExpression(pattern: "[01]{1,8}", options: .caseInsensitive)
		let entropyBytes = regex.matches(in: entropyBits, options: [], range: NSRange(location: 0, length: entropyBits.count)).map {
			UInt8(strtoul(String(entropyBits[Range($0.range, in: entropyBits)!]), nil, 2))
		}
		
		if !ignoreChecksum && (checksumBits != Mnemonic.deriveChecksumBits(entropyBytes)) {
			throw MnemonicError.invalidMnemonic
		}
		
		return entropyBytes
	}
	
	/**
	 Take a `PrivateKey` from a TorusWallet and generate a custom "shifted checksum" mnemonic, so that we can recover wallets that previously had no seed words
	 */
	public static func shiftedMnemonic(fromSpskPrivateKey pk: PrivateKey) -> Mnemonic? {
		guard let entropy = Base58Check.decode(string: pk.base58CheckRepresentation, prefix: Prefix.Keys.Secp256k1.secret) else {
			return nil
		}
		
		let data = Data(entropy)
		guard let mnemonic = try? Mnemonic(entropy: data) else {
			return nil
		}
		
		return try? shiftChecksum(mnemonic: mnemonic)
	}
	
	/**
	 Shift the checksum of of a `Mnemonic` so that it won't be accepted by tradtional improts
	 */
	public static func shiftChecksum(mnemonic: Mnemonic, wordList: WordList = WordList.english) throws -> Mnemonic {
		var mutableMnemonic = mnemonic
		guard mutableMnemonic.words.count == 24,
			  let lastWord = mutableMnemonic.words.last,
			  let shiftedWord = try? Mnemonic.getShiftedWord(word: lastWord, wordList: wordList) else {
			throw MnemonicError.invalidWordCount
		}
		
		var isValidMnemonic = (mutableMnemonic.isValid() ? 1 : 0)
		mutableMnemonic.phrase = mutableMnemonic.phrase.replacingOccurrences(of: lastWord, with: shiftedWord)
		isValidMnemonic += (mutableMnemonic.isValid() ? 1 : 0)
		
		if isValidMnemonic != 1 {
			throw MnemonicError.invalidMnemonic
		} else {
			return mutableMnemonic
		}
	}
	
	/**
	 Return a shifted word to replace the last word in a mnemonic
	 */
	public static func getShiftedWord(word: String, wordList: WordList = WordList.english) throws -> String {
		let words = wordList.words
		guard let wordIndex = words.firstIndex(of: word) else {
			throw MnemonicError.invalidWordToShift
		}
		
		let checksumByte = wordIndex % 256
		let newIndex = wordIndex - checksumByte + ((checksumByte + 128) % 256)
		
		if words.count > newIndex {
			return words[newIndex]
		} else {
			throw MnemonicError.invalidWordToShift
		}
	}
	
	/**
	 Convert a mnemonic to a Base58 encoded private key string. Helpful when determining if a shifted mnemonic is valid
	 */
	public static func mnemonicToSpsk(mnemonic: Mnemonic, wordList: WordList = WordList.english) -> String? {
		guard let bytes = try? mnemonic.toEntropy(ignoreChecksum: true, wordlist: wordList) else {
			return nil
		}
		
		return Base58Check.encode(message: bytes, prefix: Prefix.Keys.Secp256k1.secret)
	}
	
	/**
	 Convert a shifted Mnemoinc back to normal
	 */
	public static func shiftedMnemonicToMnemonic(mnemonic: Mnemonic) -> Mnemonic? {
		return try? shiftChecksum(mnemonic: mnemonic)
	}
	
	/**
	 Check if a supplied Spsk string is valid
	 */
	public static func validSpsk(_ sk: String) -> Bool {
		let canDecode = Base58Check.decode(string: sk, prefix: Prefix.Keys.Secp256k1.secret)
		
		return sk.count == 54 && canDecode != nil
	}
}
