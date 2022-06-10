//
//  String+extensions.swift
//  
//
//  Created by Simon Mcloughlin on 08/06/2022.
//

import Foundation

public extension String {
	
	init(hexEncoding data: Data) {
		self = data.hexString
	}
}
