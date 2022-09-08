import 'dart:io';

import 'package:flutter/services.dart';
import 'package:sodium_key_generator_plugin/sodium_key_generator_plugin.dart';
import 'package:local_auth/error_codes.dart' as auth_error;

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
      return key;
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
      return key;
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
      if (Platform.isWindows) {
        var pubKey1 =
            await _channel.invokeMethod('readData', {'key': "${uuid}_1_pub"});
        var privKey1 =
            await _channel.invokeMethod('readData', {'key': "${uuid}_1_priv"});
        await _channel.invokeMethod('deleteData', {'key': "${uuid}_0_pub"});
        await _channel.invokeMethod('deleteData', {'key': "${uuid}_0_priv"});
        await _channel.invokeMethod('deleteData', {'key': "${uuid}_1_pub"});
        await _channel.invokeMethod('deleteData', {'key': "${uuid}_1_priv"});
        await _channel.invokeMethod(
            'writeData', {'key': "${uuid}_0_pub", 'data': pubKey1});
        await _channel.invokeMethod(
            'writeData', {'key': "${uuid}_0_priv", 'data': privKey1});
        var edKeyPair = await SodiumKeyGeneratorPlugin.generateKey();
        await _channel.invokeMethod(
            'writeData', {'key': "${uuid}_1_pub", 'data': edKeyPair.pubKey});
        await _channel.invokeMethod(
            'writeData', {'key': "${uuid}_1_priv", 'data': edKeyPair.privKey});
      } else {
        await _channel.invokeMethod("rotateForEd25519", {'uuid': uuid});
      }
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Signs provided message using Ed25519. Returns signature if successfully signed.
  Future<String> sign(String message) async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      if (Platform.isWindows) {
        var key =
            await _channel.invokeMethod('readData', {'key': "${uuid}_0_priv"});
        final LocalAuthentication auth = LocalAuthentication();
        try {
          final bool didAuthenticate = await auth.authenticate(
              localizedReason: 'Please authenticate to show account balance',
              options: const AuthenticationOptions(useErrorDialogs: false));
          if (didAuthenticate) {
            var signature =
                await SodiumKeyGeneratorPlugin.signMessage(message, key);
            print(signature);
            return signature;
          } else {
            throw SigningFailureException('Signing the message has failed.');
          }
        } on PlatformException catch (e) {
          throw SigningFailureException('Signing the message has failed.');
        }
      } else {
        var signature = await _channel
            .invokeMethod("signEd25519", {'uuid': uuid, 'message': message});
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
