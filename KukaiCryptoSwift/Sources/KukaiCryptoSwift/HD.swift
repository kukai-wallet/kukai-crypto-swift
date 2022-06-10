//
//  HD.swift
//  
//
//  Created by Simon Mcloughlin on 09/06/2022.
//
// Converted to Swift from: https://github.com/tezos-commons/tezos-core-tools/blob/master/packages/crypto-utils/src/hd.ts

import Foundation
import CryptoKit
import BigInt
import Sodium

/// A struct used to provide a number of functions needed to handle derivation paths and derive nodes for creating HD key pairs
public struct HD {
	
	/// Default Tezos derivation path
	public static let defaultDerivationPath = "m/44'/1729'/0'/0'"
	
	// MARK: - Types
	
	/// Errors that can be thrown
	public enum HDError: Error {
		case invalidHmac
		case invalidDerivationPath
		case derivationPathTooLarge
		case invalidSeedSize
		case unableToCreateKeyPair
		case unableToCreatePublicKey
	}
	
	/// A struct representing a Node in a HD chain
	public struct Node {
		let privateKey: Data
		let chainCode: Data
	}
	
	
	
	// MARK: - Hashing
	
	/// Compute a HMAC using SHA512
	public static func hmac(message: Data, key: Data) -> Data {
		var hmac = HMAC<SHA512>(key: SymmetricKey(data: key))
		hmac.update(data: message)
		
		return Data(hmac.finalize())
	}
	
	
	
	// MARK: - Derive Nodes
	
	/// Derive a nnode from a message and a key
	public static func deriveNode(message: Data, key: Data) throws -> Node {
		let hmac = hmac(message: message, key: key)
		
		if hmac.count < 64 {
			throw HDError.invalidHmac
		}
		
		return Node(privateKey: hmac.prefix(32), chainCode: hmac.suffix(from: 32))
	}
	
	/// Derive the root (or master) node from cryptographic seed data
	public static func deriveRootNode(seed: Data) throws -> Node {
		if seed.count != 64 {
			throw HDError.invalidSeedSize
		}
		
		let domainSeperator = "ed25519 seed".bytes
		return try deriveNode(message: seed, key: Data(bytes: domainSeperator, count: domainSeperator.count));
	}
	
	/// Derive a child node from a `Node` and a given index
	public static func deriveChildNode(node: Node, index: BigUInt) throws -> Node {
		let message = (Data(repeating: 0, count: 1) + node.privateKey + index.serialize())
		
		return try deriveNode(message: message, key: node.chainCode)
	}
	
	
	
	// MARK: - Helpers
	
	/// Convert a derivation path into an array of `BigUInt` so it can be interated
	public static func convertDerivationPathToArray(_ derivationPath: String) throws -> [BigUInt] {
		var path = derivationPath.replacingOccurrences(of: "m/", with: "")
		path = path.replacingOccurrences(of: "'", with: "h")
		
		if !validateDerivationPath(path) {
			throw HDError.invalidDerivationPath
		}
		
		let max = BigUInt("2147483648") // 0x80000000
		let pathArray = try path.components(separatedBy: "/").map { component -> BigUInt in
			let level = String(component.prefix(component.count - 1))
			if let levelInt = BigUInt(level) {
				if levelInt >= max {
					throw HDError.derivationPathTooLarge
				}
				
				return levelInt + max
				
			} else {
				throw HDError.invalidDerivationPath
			}
		}
		
		return pathArray
	}
	
	/// Very basic validation of a derivation path
	public static func validateDerivationPath(_ derivationPath: String) -> Bool {
		if (derivationPath.prefix(12) == "m/44'/1729'/" && derivationPath.count >= 14) ||
			(derivationPath.prefix(10) == "44h/1729h/" && derivationPath.count >= 12) {
			return true
		}
		
		return false
	}
}
