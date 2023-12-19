//
//  PrivateKey.swift
//  
//
//  Created by Simon Mcloughlin on 08/06/2022.
//

import Foundation
import secp256k1
import Sodium


/// A struct representing a PrivateKey
public struct PrivateKey: Codable {
	
	
	// MARK: - Properties
	
	/// The raw bytes of the private key
	public var bytes: [UInt8]
	
	/// The signing curve used by the public key, to generate a wallet address
	public let signingCurve: EllipticalCurve
	
	/// Return a Base58 encoded version of the privateKey
	public var base58CheckRepresentation: String {
		switch signingCurve {
			case .ed25519:
				return Base58Check.encode(message: bytes, prefix: Prefix.Keys.Ed25519.secret)
				
			case .secp256k1:
				return Base58Check.encode(message: bytes, prefix: Prefix.Keys.Secp256k1.secret)
		}
	}
	
	
	
	// MARK: - Init
	
	/**
	 Initialize a key with the given bytes.
	 - parameter bytes: Raw bytes of the private key.
	 - parameter signingCurve: The elliptical curve to use for the key. Defaults to ed25519.
	 */
	public init(_ bytes: [UInt8], signingCurve: EllipticalCurve = .ed25519) {
		self.bytes = bytes
		self.signingCurve = signingCurve
	}
	
	/**
	 Initialize a key with the given base58check encoded string.
	 - parameter string: A base58check encoded string.
	 - parameter signingCurve: The elliptical curve to use for the key. Defaults to ed25519.
	 */
	public init?(_ string: String, signingCurve: EllipticalCurve = .ed25519) {
		switch signingCurve {
			case .ed25519:
				guard let bytes = Base58Check.decode(string: string, prefix: Prefix.Keys.Ed25519.secret) else {
					return nil
				}
				self.init(bytes)
				
			case .secp256k1:
				guard let bytes = Base58Check.decode(string: string, prefix: Prefix.Keys.Secp256k1.secret) else {
					return nil
				}
				self.init(bytes, signingCurve: .secp256k1)
		}
	}
	
	
	
	// MARK: - Utils
	
	/**
	 Sign the given hex encoded string with the given key.
	 - parameter hex: The hex string to sign.
	 - Returns: A signature from the input.
	 */
	public func sign(hex: String) -> [UInt8]? {
		guard let bytes = Sodium.shared.utils.hex2bin(hex) else {
			return nil
		}
		return self.sign(bytes: bytes)
	}
	
	/**
	 Sign the given bytes.
	 - parameter bytes: The raw bytes to sign.
	 - Returns: A signature from the input.
	 */
	public func sign(bytes: [UInt8]) -> [UInt8]? {
		switch signingCurve {
			case .ed25519:
				return Sodium.shared.sign.signature(message: bytes, secretKey: self.bytes)
				
			case .secp256k1:
				var signature = secp256k1_ecdsa_signature()
				let signatureLength = 64
				var output = [UInt8](repeating: 0, count: signatureLength)
				
				guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)), self.bytes.count == 64 else {
					return nil
				}
				
				defer {
					secp256k1_context_destroy(context)
				}
				
				
				guard secp256k1_ecdsa_sign(context, &signature, bytes, self.bytes, nil, nil) != 0,
					  secp256k1_ecdsa_signature_serialize_compact(context, &output, &signature) != 0
				else {
					return nil
				}
				
				return output
		}
	}
}

extension PrivateKey: CustomStringConvertible {
	
	public var description: String {
		return base58CheckRepresentation
	}
}

extension PrivateKey: Equatable {
	
	public static func == (lhs: PrivateKey, rhs: PrivateKey) -> Bool {
		return lhs.base58CheckRepresentation == rhs.base58CheckRepresentation
	}
}
