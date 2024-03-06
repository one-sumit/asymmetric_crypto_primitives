import 'dart:io';
import 'dart:convert';

import 'package:flutter/services.dart';

import 'package:local_auth/local_auth.dart';
import 'exceptions.dart';

class Ed25519Signer {
  static const MethodChannel _channel =
      MethodChannel('asymmetric_crypto_primitives');
  String uuid;

  ///Constructor for Ed25519 signer.
  Ed25519Signer(this.uuid);

  ///Returns currently used public key for Ed25519 signer.
  Future<String> getCurrentPubKey() async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      var key =
          await _channel.invokeMethod("readData", {'key': "${uuid}_0_pub"});
      if (Platform.isAndroid) {
        var codec = const Base64Codec();
        var encodeKey = codec.decode(key);
        var urlCodec = const Base64Codec.urlSafe();
        var urlSafeKey = urlCodec.encode(encodeKey);
        return urlSafeKey;
      } else {
        return key;
      }
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Returns second/backup public key for Ed25519 signer.
  Future<String> getNextPubKey() async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      var key =
          await _channel.invokeMethod("readData", {'key': "${uuid}_1_pub"});
      var codec = const Base64Codec();
      var encodeKey = codec.decode(key);
      var urlCodec = const Base64Codec.urlSafe();
      var urlSafeKey = urlCodec.encode(encodeKey);
      return urlSafeKey;
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Returns the uuid of Ed25519 signer.
  Future<String> getUuid() async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      return uuid.toString();
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Rotates the keys (the backup key becomes currently used and new key is generated as backup).
  Future<void> rotateForEd25519() async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      await _channel.invokeMethod("rotateForEd25519", {'uuid': uuid});
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Signs provided message using Ed25519. Returns signature if successfully signed.
  Future<String> sign(String message, String prompt, String subPrompt) async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      var signature = await _channel.invokeMethod("signEd25519", {
        'uuid': uuid,
        'message': message,
        'prompt': prompt,
        'subPrompt': subPrompt
      });
      if (signature != false) {
        return signature;
      } else {
        throw SigningFailureException('Signing the message has failed.');
      }
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  Future<String> signNoAuth(String message) async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      if (Platform.isMacOS) {
        throw PlatformNotSupportedException(
            'MacOS and iOS are not supported when it comes to authentication-free signing.');
      } else {
        var signature = await _channel.invokeMethod(
            "signEd25519NoAuth", {'uuid': uuid, 'message': message});
        if (signature != false) {
          return signature;
        } else {
          throw SigningFailureException('Signing the message has failed.');
        }
      }
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }
}
