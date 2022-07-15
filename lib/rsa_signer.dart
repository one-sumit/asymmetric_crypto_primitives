import 'package:flutter/services.dart';

import 'exceptions.dart';

class RSASigner {
  static const MethodChannel _channel = MethodChannel('asymmetric_crypto_primitives');
  String uuid;

  ///Constructor for RSA signer.
  RSASigner(this.uuid);

  ///Returns currently used public key for RSA signer.
  Future<String> getCurrentPubKey() async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      var key =
          await _channel.invokeMethod("getRSAKey", {'alias': "${uuid}_0_rsa"});
      return key;
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Returns second/backup public key for RSA signer.
  Future<String> getNextPubKey() async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      var key =
          await _channel.invokeMethod("getRSAKey", {'alias': "${uuid}_1_rsa"});
      return key;
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Returns the uuid of RSA signer.
  Future<String> getUuid() async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      return uuid;
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Rotates the keys (the backup key becomes currently used and new key is generated as backup).
  Future<void> rotateForRSA() async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      await _channel.invokeMethod("rotateForRSA", {'uuid': uuid});
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Signs provided message using RSA. Returns signature if successfully signed.
  Future<String> sign(String message) async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      var signature = await _channel
          .invokeMethod("signRSA", {'uuid': uuid, 'message': message});
      return signature;
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }
}
