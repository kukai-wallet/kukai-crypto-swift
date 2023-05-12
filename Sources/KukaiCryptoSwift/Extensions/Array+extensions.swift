//
//  Array+extensions.swift
//  
//
//  Created by Simon Mcloughlin on 12/05/2023.
//

import Foundation
import Sodium

public extension Array where Element == UInt8 {
	
	/// Prepare bytes for signing by applying a watermark and hashing.
	func addOperationWatermarkAndHash() -> [UInt8]? {
		let watermarkedOperation = Prefix.Watermark.operation + self
		return Sodium.shared.genericHash.hash(message: watermarkedOperation, outputLength: 32)
	}
}
