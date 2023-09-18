//
//  PublicKey.swift
//  
//
//  Created by Simon Mcloughlin on 08/06/2022.
//

import Foundation
import secp256k1
import Sodium


/// A struct representing a PublicKey
public struct PublicKey: Codable {
	
	
	// MARK: - Properties
	
	/// The raw bytes of the public key
	public var bytes: [UInt8]
	
	/// The signing curve used by the public key, to generate a wallet address
	public let signingCurve: EllipticalCurve
	
	/// Return a Base58 encoded version of the publicKey
	public var base58CheckRepresentation: String {
		switch signingCurve {
			case .ed25519:
				return Base58Check.encode(message: bytes, prefix: Prefix.Keys.Ed25519.public)
				
			case .secp256k1:
				return Base58Check.encode(message: bytes, prefix: Prefix.Keys.Secp256k1.public)
		}
	}
	
	/// Return a hash of the publicKey with the appropriate address prefix
	public var publicKeyHash: String? {
		guard let hash = Sodium.shared.genericHash.hash(message: bytes, outputLength: 20) else {
			return nil
		}
		
		switch signingCurve {
			case .ed25519:
				return Base58Check.encode(message: hash, prefix: Prefix.Address.tz1)
				
			case .secp256k1:
				return Base58Check.encode(message: hash, prefix: Prefix.Address.tz2)
		}
	}
	
	
	
	// MARK: - Init
	
	/// Initialize a key with the given bytes and signing curve.
	public init(_ bytes: [UInt8], signingCurve: EllipticalCurve = .ed25519) {
		self.bytes = bytes
		self.signingCurve = signingCurve
	}
	
	
	
	// MARK: - Utils
	
	/**
	 Verify that the given signature matches the given input hex.
	 - parameter signature: The proposed signature of the bytes.
	 - parameter hex: The hex to check.
	 - Returns: True if the public key and signature match the given bytes.
	 */
	public func verify(message: [UInt8], signature: [UInt8], hex: String) -> Bool {
		guard let bytes = Sodium.shared.utils.hex2bin(hex) else {
			return false
		}
		return verify(message: message, signature: signature, bytes: bytes)
	}
	
	/**
	 Verify that the given signature matches the given input bytes.
	 - parameter signature: The proposed signature of the bytes.
	 - parameter bytes: The bytes to check.
	 - Returns: True if the public key and signature match the given bytes.
	 */
	public func verify(message: [UInt8], signature: [UInt8], bytes: [UInt8]) -> Bool {
		switch signingCurve {
			case .ed25519:
				return Sodium.shared.sign.verify(message: message, publicKey: self.bytes, signature: signature)
				
			case .secp256k1:
				let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY))
				defer {
					secp256k1_context_destroy(context)
				}
				
				var cSignature = secp256k1_ecdsa_signature()
				var publicKey = secp256k1_pubkey()
				secp256k1_ecdsa_signature_parse_compact(context!, &cSignature, signature)
				_ = secp256k1_ec_pubkey_parse(context!, &publicKey, self.bytes, self.bytes.count)
				
				return secp256k1_ecdsa_verify(context!, &cSignature, message, &publicKey) == 1
		}
	}
}

extension PublicKey: CustomStringConvertible {
	
	public var description: String {
		return base58CheckRepresentation
	}
}

extension PublicKey: Equatable {
	
	public static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
		return lhs.base58CheckRepresentation == rhs.base58CheckRepresentation
	}
}
