//
//  Sodium+extensions.swift
//  
//
//  Created by Simon Mcloughlin on 08/06/2022.
//

import Foundation
import Sodium

/// Extension to `Sodium`to add a static shared instance, to avoid having to load it into memory frequently
extension Sodium {
	
	public static let shared = Sodium()
}
