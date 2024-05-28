//
//  Data+extensions.swift
//  
//
//  Created by Simon Mcloughlin on 08/06/2022.
//

import Foundation
import Security

private let charA = UInt8(UnicodeScalar("a").value)
private let char0 = UInt8(UnicodeScalar("0").value)

public enum RandomBytesError: Error {
	case failed(OSStatus)
}

public enum ByteHexEncodingErrors: Error {
	case incorrectHexValue
	case incorrectString
}

private func itoh(_ value: UInt8) -> UInt8 {
	return (value > 9) ? (charA + value - 10) : (char0 + value)
}

private func htoi(_ value: UInt8) throws -> UInt8 {
	switch value {
		case char0...char0 + 9:
			return value - char0
		case charA...charA + 5:
			return value - charA + 10
		default:
			throw ByteHexEncodingErrors.incorrectHexValue
	}
}

public extension Data {
	
	/// Generate secure random bytes from Data
	static func randomBytes(_ count: Int) throws -> Data {
		var buffer = Data(count: count)
		try buffer.withUnsafeMutableBytes { pointer in
			guard let bytes = pointer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
				throw RandomBytesError.failed(errSecAllocate)
			}
			let status = SecRandomCopyBytes(kSecRandomDefault, count, bytes)
			guard status == errSecSuccess else {
				throw RandomBytesError.failed(status)
			}
		}
		return buffer
	}
	
	/// Create a Data object from a hex string
	init(hexString: String) throws {
		self.init()
		
		if hexString.count % 2 != 0 || hexString.count == 0 {
			throw ByteHexEncodingErrors.incorrectString
		}
		
		let stringBytes: [UInt8] = Array(hexString.data(using: String.Encoding.utf8)!)
		
		for i in 0...((hexString.count / 2) - 1) {
			let char1 = stringBytes[2 * i]
			let char2 = stringBytes[2 * i + 1]
			
			try self.append(htoi(char1) << 4 + htoi(char2))
		}
	}
	
	func bytes() -> [UInt8] {
		return [UInt8](self)
	}
}

public extension [UInt8] {
	
	func data() -> Data {
		return Data(self)
	}
}

public extension DataProtocol {
	
	/// Convert a Data object into a hex string
	var hexString: String {
		let hexLen = self.count * 2
		let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: hexLen)
		var offset = 0
		
		self.regions.forEach { (_) in
			for i in self {
				ptr[Int(offset * 2)] = itoh((i >> 4) & 0xF)
				ptr[Int(offset * 2 + 1)] = itoh(i & 0xF)
				offset += 1
			}
		}
		
		return String(bytesNoCopy: ptr, length: hexLen, encoding: .utf8, freeWhenDone: true)!
	}
}
