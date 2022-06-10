//
//  FixedWidthIntegar+extensions.swift
//  
//
//  Created by Simon Mcloughlin on 09/06/2022.
//

import Foundation

extension FixedWidthInteger {
	
	init?<D: DataProtocol>(data: D) {
		guard let value = Self(data.hexString, radix: 16) else {
			return nil
		}
		self = value
	}
	
	public var bytes: [UInt8] {
		withUnsafeBytes(of: self.byteSwapped, Array.init)
	}
}
