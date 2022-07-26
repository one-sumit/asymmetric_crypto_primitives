//
//  Generated file. Do not edit.
//

import FlutterMacOS
import Foundation

import asymmetric_crypto_primitives

func RegisterGeneratedPlugins(registry: FlutterPluginRegistry) {
    if #available(macOS 10.15, *) {
        AsymmetricCryptoPrimitivesPlugin.register(with: registry.registrar(forPlugin: "AsymmetricCryptoPrimitivesPlugin"))
    } else {
        // Fallback on earlier versions
    }
}
