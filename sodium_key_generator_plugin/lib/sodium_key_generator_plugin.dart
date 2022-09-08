import 'dart:ffi';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart';
import 'package:sodium_key_generator_plugin/exceptions.dart';

import 'bridge_generated.dart';

class SodiumKeyGeneratorPlugin {
  static const base = 'sodium_key_generator';
  static const path = '$base.dll';
  static final dylib = DynamicLibrary.open(path);
  static final api = SodiumKeyGeneratorImpl(dylib);

  static Future<EdKeyPair> generateKey() async {
    try {
      var edKeyPair = await api.generateKey();
      return edKeyPair;
    } on FfiException catch (e) {
      if (e.message.contains('initialization')) {
        throw InitializationFailedException(
            'Sodium library initialization failed. Contact the developer of the plugin.');
      }
      rethrow;
    }
  }

  static Future<String> signMessage(String message, String key) async {
    try {
      var signature = await api.signMessage(message: message, key: key);
      return signature;
    } on FfiException catch (e) {
      if (e.message.contains('initialization')) {
        throw InitializationFailedException(
            'Sodium library initialization failed. Contact the developer of the plugin.');
      } else if (e.message.contains('decoding')) {
        throw KeyDecodingFailedException(
            'Base64 decoding of the key has failed. Check the key format in database.');
      } else if (e.message.contains('transforming')) {
        throw KeyTransformingFailedException(
            'Transformsation from String to SecretKey has failed. Check the key format in database.');
      }
      rethrow;
    }
  }
}
