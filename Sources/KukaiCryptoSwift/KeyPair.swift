//
//  KeyPair.swift
//  
//
//  Created by Simon Mcloughlin on 10/06/2022.
//

import Foundation
import Sodium
import secp256k1
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
			os_log("KeyPair Error - regular: %@", log: .default, type: .error, "\(error)")
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
			os_log("KeyPair Error - HD: %@", log: .default, type: .error, "\(error)")
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
			os_log("KeyPair Error - HD: %@", log: .default, type: .error, "\(error)")
			return nil
		}
	}
	
	
	
	// MARK: - Helpers
	
	/// Helper method to take a secp256k1 private key (for a regualr keypair) and use it to create a public key for the same curve
	public static func secp256k1PublicKey(fromPrivateKeyBytes pkBytes: [UInt8]) -> PublicKey? {
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
}
