//
//  KeyPair.swift
//  
//
//  Created by Simon Mcloughlin on 10/06/2022.
//

import Foundation
import Sodium
import secp256k1
import CommonCrypto
import os.log

/// Distingush between ed25519 (TZ1...) and secp256k1 (TZ2...) curves for creating and using wallet addresses
public enum EllipticalCurve: String, Codable {
	case ed25519
	case secp256k1
	
	public static func fromAddress(_ address: String) -> EllipticalCurve? {
		let prefix = address.lowercased().prefix(3)
		
		if prefix == "tz1" { return .ed25519 }
		else if prefix == "tz2" { return .secp256k1 }
		else { return nil }
	}
	
	public static func fromBase58Key(_ key: String) -> EllipticalCurve? {
		let prefix = key.lowercased().prefix(4)
		
		if prefix == "edpk" { return .ed25519 }
		else if prefix == "sppk" { return .secp256k1 }
		else { return nil }
	}
}

/// A struct representing a both a `PrivateKey` and `PublicKey` with helper methods to create various kinds
public struct KeyPair {
	
	/// The underlying `PrivateKey` of the pair
	public let privateKey: PrivateKey
	
	/// The underlying `PublicKey` of the pair
	public let publicKey: PublicKey
	
	
	
	// MARK: - Public Helpers
	
	/**
	 Create a regular (non HD) `KeyPair` from a hex seed string
	 - parameter seedString: A hex string representing a cryptographic seed (can be created from `Mnemonic`)
	 - Returns: A `KeyPair` instance, if able, nil otherwise
	 */
	public static func regular(fromSeedString seedString: String) -> KeyPair? {
		var shortenedSeed = seedString
		if seedString.count > 64 {
			shortenedSeed = String(seedString[..<seedString.index(seedString.startIndex, offsetBy: 64)])
		}
		
		guard let seed = Sodium.shared.utils.hex2bin(shortenedSeed), let keyPair = Sodium.shared.sign.keyPair(seed: seed) else {
			return nil
		}
		
		let secretKeyBytes = keyPair.secretKey
		let publicKeyBytes = keyPair.publicKey
		
		return KeyPair(privateKey: PrivateKey(secretKeyBytes, signingCurve: .ed25519), publicKey: PublicKey(publicKeyBytes, signingCurve: .ed25519))
	}
	
	/**
	 Create a regular (non HD) `KeyPair` from a `Mnemonic` instance
	 - parameter mnemonic: An instance of `Mnemonic`
	 - Returns: A `KeyPair` instance, if able, nil otherwise
	 */
	public static func regular(fromMnemonic mnemonic: Mnemonic, passphrase: String) -> KeyPair? {
		do {
			let seed = try mnemonic.seed(passphrase: passphrase).hexString
			return regular(fromSeedString: seed)
			
		} catch (let error) {
			Logger().error("KeyPair Error - regular: \(error)")
			return nil
		}
	}
	
	/**
	 Create a `KeyPair` from a Base58 Check encoded secret key, optionaly encrypted with a passphrase.
	 Supports both Tz1 (edsk...   edes...) and Tz2 (spsk...   spes...)
	 */
	public static func regular(fromSecretKey secretKey: String, andPassphrase: String?) -> KeyPair? {
		let first4 = secretKey.prefix(4)
		
		switch first4 {
			case "edsk":
				let is54Chars = (secretKey.count == 54)
				let prefix = is54Chars ? Prefix.Keys.Ed25519.seed : Prefix.Keys.Ed25519.secret
				guard let decoded = Base58Check.decode(string: secretKey, prefix: prefix), let keyPair = Sodium.shared.sign.keyPair(seed: Array(decoded.prefix(32))) else {
					return nil
				}
				
				return KeyPair(privateKey: PrivateKey(keyPair.secretKey), publicKey: PublicKey(keyPair.publicKey))
				
			case "edes":
				guard let password = andPassphrase else {
					return nil
				}
				
				return KeyPair.decryptSecretKey(secretKey, ellipticalCurve: .ed25519, passphrase: password)
				
			case "spsk":
				guard let decoded = Base58Check.decode(string: secretKey, prefix: Prefix.Keys.Secp256k1.secret) else {
					return nil
				}
				
				let privateKey = PrivateKey(decoded, signingCurve: .secp256k1)
				guard let publicKey = KeyPair.secp256k1PublicKey(fromPrivateKeyBytes: privateKey.bytes) else {
					return nil
				}
				
				return KeyPair(privateKey: privateKey, publicKey: publicKey)
				
			case "spes":
				guard let password = andPassphrase else {
					return nil
				}
				
				return KeyPair.decryptSecretKey(secretKey, ellipticalCurve: .secp256k1, passphrase: password)
				
			default:
				return nil
		}
	}
	
	/**
	 Create a HD `KeyPair` from a hex seed string and optional Derivation Path (defaults to m/44'/1729'/0'/0' ). Only TZ1 are produceable
	 - parameter seedString: A hex string representing a cryptographic seed (can be created from `Mnemonic`)
	 - parameter derivationPath: The derivationPath to use
	 - Returns: A `KeyPair` instance, if able, nil otherwise
	 */
	public static func hd(fromSeedString seedString: String, andDerivationPath derivationPath: String = HD.defaultDerivationPath) -> KeyPair? {
		
		do {
			let pathArray = try HD.convertDerivationPathToArray(derivationPath)
			var node = try HD.deriveRootNode(seed: Data(hexString: seedString))
			
			for bigInt in pathArray {
				node = try HD.deriveChildNode(node: node, index: bigInt)
			}
			
			guard let data = Sodium.shared.utils.hex2bin(node.privateKey.hexString), let keyPair = Sodium.shared.sign.keyPair(seed: data) else {
				return nil
			}
			
			return KeyPair(privateKey: PrivateKey(keyPair.secretKey), publicKey: PublicKey(keyPair.publicKey))
			
		} catch (let error) {
			Logger().error("KeyPair Error - regular: \(error)")
			return nil
		}
	}
	
	/**
	 Create a HD `KeyPair` from a `Mnemonic` instance
	 - parameter mnemonic: An instance of `Mnemonic`
	 - parameter derivationPath: The derivationPath to use
	 - Returns: A `KeyPair` instance, if able, nil otherwise
	 */
	public static func hd(fromMnemonic mnemonic: Mnemonic, passphrase: String, andDerivationPath derivationPath: String = HD.defaultDerivationPath) -> KeyPair? {
		do {
			let seed = try mnemonic.seed(passphrase: passphrase).hexString
			return hd(fromSeedString: seed, andDerivationPath: derivationPath)
			
		} catch (let error) {
			Logger().error("KeyPair Error - regular: \(error)")
			return nil
		}
	}
	
	
	
	// MARK: - Helpers
	
	/// Helper method to take a secp256k1 private key (for a regualr keypair) and use it to create a public key for the same curve
	public static func secp256k1PublicKey(fromPrivateKeyBytes pkBytes: [UInt8]) -> PublicKey? {
		if pkBytes.count != 32 {
			return nil
		}
		
		var publicKey = secp256k1_pubkey()
		var outputLength = 33
		var publicKeyBytes = [UInt8](repeating: 0, count: outputLength)
		
		guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
			return nil
		}
		
		defer {
			secp256k1_context_destroy(context)
		}
		
		guard secp256k1_ec_pubkey_create(context, &publicKey, pkBytes) != 0,
			  secp256k1_ec_pubkey_serialize(context, &publicKeyBytes, &outputLength, &publicKey, UInt32(SECP256K1_EC_COMPRESSED)) != 0
		else {
			return nil
		}
		
		return PublicKey(publicKeyBytes, signingCurve: .secp256k1)
	}
	
	/// Helper method to uncompress a secp256k1 public key
	public static func secp256k1PublicKey_uncompressed(fromBytes: [UInt8]) -> [UInt8] {
		if fromBytes.count != 32 {
			return []
		}
		
		var publicKey = secp256k1_pubkey()
		var outputLength = 65
		var outputBytes = [UInt8](repeating: 0, count: outputLength)
		
		guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)) else {
			return []
		}
		
		defer {
			secp256k1_context_destroy(context)
		}
		
		guard secp256k1_ec_pubkey_parse(context, &publicKey, fromBytes, fromBytes.count) != 0,
			  secp256k1_ec_pubkey_serialize(context, &outputBytes, &outputLength, &publicKey, UInt32(SECP256K1_EC_UNCOMPRESSED)) != 0 else {
			return []
		}
		
		return outputBytes
	}
	
	public static func decryptSecretKey(_ secretKey: String, ellipticalCurve: EllipticalCurve, passphrase: String) -> KeyPair? {
		var decoded: [UInt8]? = nil
		
		switch ellipticalCurve {
			case .ed25519:
				decoded = Base58Check.decode(string: secretKey, prefix: Prefix.Keys.Ed25519.encrypted)
				
			case .secp256k1:
				decoded = Base58Check.decode(string: secretKey, prefix: Prefix.Keys.Secp256k1.encrypted)
		}
		
		guard let minusPrefix = decoded else {
			return nil
		}
		
		let salt = Array(minusPrefix.prefix(8))
		let encryptedSk = Array(minusPrefix.suffix(from: 8))
		guard let key = pbkdf2(password: passphrase, saltData: salt.data(), keyByteCount: 32, prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512), rounds: 32768),
			  let box = Sodium.shared.secretBox.open(authenticatedCipherText: encryptedSk, secretKey: key.bytes(), nonce: Array(repeating: 0, count: 24)) else {
			return nil
		}
		
		
		var keyPair: KeyPair? = nil
		switch ellipticalCurve {
			case .ed25519:
				guard let res = Sodium.shared.sign.keyPair(seed: box) else {
					return nil
				}
				
				keyPair = KeyPair(privateKey: PrivateKey(res.secretKey), publicKey: PublicKey(res.publicKey))
				
			case .secp256k1:
				let privateKey = PrivateKey(box, signingCurve: .secp256k1)
				guard let publicKey = KeyPair.secp256k1PublicKey(fromPrivateKeyBytes: privateKey.bytes) else {
					return nil
				}
				
				keyPair = KeyPair(privateKey: privateKey, publicKey: publicKey)
		}
		
		return keyPair
	}
	
	public static func pbkdf2(password: String, saltData: Data, keyByteCount: Int, prf: CCPseudoRandomAlgorithm, rounds: Int) -> Data? {
		guard let passwordData = password.data(using: .utf8) else { return nil }
		var derivedKeyData = Data(repeating: 0, count: keyByteCount)
		let derivedCount = derivedKeyData.count
		let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
			let keyBuffer: UnsafeMutablePointer<UInt8> =
			derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
			return saltData.withUnsafeBytes { saltBytes -> Int32 in
				let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
				return CCKeyDerivationPBKDF(
					CCPBKDFAlgorithm(kCCPBKDF2),
					password,
					passwordData.count,
					saltBuffer,
					saltData.count,
					prf,
					UInt32(rounds),
					keyBuffer,
					derivedCount)
			}
		}
		return derivationStatus == kCCSuccess ? derivedKeyData : nil
	}
	
	public static func isSecretKeyEncrypted(_ secret: String) -> Bool {
		let prefix = secret.prefix(4)
		
		return prefix == "edes" || prefix == "spes"
	}
}
