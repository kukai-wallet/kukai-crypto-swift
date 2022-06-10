
import Foundation
import CommonCrypto

public enum MnemonicError: Swift.Error {
	case seedDerivationFailed
	case seedPhraseInvalid(String)
	case error(Swift.Error)
}

/**
 * A list of words which can generate a private key.
 */
public struct Mnemonic: Equatable {
	/// The list of words as a single sentence.
	public private(set) var phrase: String = ""
	
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
}
