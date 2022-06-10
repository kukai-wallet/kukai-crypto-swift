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

public struct KeyPair {
	
	let privateKey: PrivateKey
	let publicKey: PublicKey
	
	public static func regular(fromSeedString seedString: String, andSigningCurve signingCurve: EllipticalCurve = .ed25519) -> KeyPair? {
		guard let seed = Sodium.shared.utils.hex2bin(seedString), let keyPair = Sodium.shared.sign.keyPair(seed: seed) else {
			return nil
		}
		
		let secretKeyBytes = keyPair.secretKey
		let publicKeyBytes = keyPair.publicKey
		
		switch signingCurve {
			case .ed25519:
				return KeyPair(privateKey: PrivateKey(secretKeyBytes, signingCurve: signingCurve), publicKey: PublicKey(publicKeyBytes, signingCurve: signingCurve))
				
			case .secp256k1:
				let privateKeyBytes = Array(secretKeyBytes[..<32])
				let privateKey = PrivateKey(privateKeyBytes, signingCurve: signingCurve)
				
				guard let publicKey = secp256k1PublicKey(fromPrivateKeyBytes: privateKeyBytes) else {
					return nil
				}
				
				return KeyPair(privateKey: privateKey, publicKey: publicKey)
		}
	}
	
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
			os_log("KeyPair Error: %@", log: .default, type: .error, "\(error)")
			return nil
		}
	}
	
	
	private static func secp256k1PublicKey(fromPrivateKeyBytes pkBytes: [UInt8]) -> PublicKey? {
		var publicKey = secp256k1_pubkey()
		var outputLength = 33
		var publicKeyBytes = [UInt8](repeating: 0, count: outputLength)
		
		guard let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN)),
			  secp256k1_ec_pubkey_create(context, &publicKey, pkBytes) != 0,
			  secp256k1_ec_pubkey_serialize(context, &publicKeyBytes, &outputLength, &publicKey, UInt32(SECP256K1_EC_COMPRESSED)) != 0
		else {
			return nil
		}
		
		defer {
			secp256k1_context_destroy(context)
		}
		
		return PublicKey(publicKeyBytes, signingCurve: .secp256k1)
	}
}
