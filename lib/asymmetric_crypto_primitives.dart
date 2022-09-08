import 'package:asymmetric_crypto_primitives/rsa_signer.dart';
import 'package:flutter/services.dart';
import 'package:nacl_win/bridge_generated.dart';
import 'package:uuid/uuid.dart';
import 'package:nacl_win/nacl_win.dart';
import 'dart:io';

import 'ed25519_signer.dart';
import 'exceptions.dart';

class AsymmetricCryptoPrimitives {
  static const MethodChannel _channel =
      MethodChannel('asymmetric_crypto_primitives');

  ///Initializes the Ed25519 signer object, which will allow the user to generate keys,
  ///rotate them and delete them.
  static Future<Ed25519Signer> establishForEd25519() async {
    if (Platform.isWindows) {
      String uuid = const Uuid().v4().toString();
      EdKeyPair keyPair0 = await NaclWin.generateKey();
      await writeData("${uuid}_0_pub", keyPair0.pubKey);
      await writeData("${uuid}_0_priv", keyPair0.privKey);
      EdKeyPair keyPair1 = await NaclWin.generateKey();
      await writeData("${uuid}_1_pub", keyPair1.pubKey);
      await writeData("${uuid}_1_priv", keyPair1.privKey);
      return Ed25519Signer(uuid);
    } else {
      var isDeviceSecure = await checkIfDeviceSecure();
      if (isDeviceSecure) {
        String uuid = const Uuid().v4().toString();
        await _channel.invokeMethod('establishForEd25519', {'uuid': uuid});
        return Ed25519Signer(uuid);
      } else {
        throw DeviceNotSecuredException(
            'Secure lock on this device is not set up. Consider setting a pin or pattern.');
      }
    }
  }

  ///Returns the Ed25519 signer object from given uuid
  static Future<Ed25519Signer> getEd25519SignerFromUuid(String uuid) async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      return Ed25519Signer(uuid);
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Returns the RSA signer object from given uuid
  static Future<RSASigner> getRSASignerFromUuid(String uuid) async {
    var isCorrectUuid =
        await _channel.invokeMethod('checkUuid', {'uuid': uuid});
    if (isCorrectUuid) {
      return RSASigner(uuid);
    } else {
      throw IncorrectUuidException(
          'There are no keys associated with this UUID saved on the device');
    }
  }

  ///Initializes the RSA signer object, which will allow the user to generate keys,
  ///rotate them and delete them.
  static Future<RSASigner> establishForRSA() async {
    var isDeviceSecure = await checkIfDeviceSecure();
    if (isDeviceSecure) {
      String uuid = const Uuid().v4().toString();
      await _channel.invokeMethod('establishForRSA', {'uuid': uuid});
      return RSASigner(uuid);
    } else {
      throw DeviceNotSecuredException(
          'Secure lock on this device is not set up. Consider setting a pin or pattern.');
    }
  }

  ///Deletes the keys established by signer with particular uuid
  static Future<void> cleanUp(dynamic signer) async {
    await _channel.invokeMethod('cleanUp', {'uuid': await signer.getUuid()});
    signer = null;
  }

  ///Checks if the screen lock has been set on the device. Returns true if it is set and false if not. An asynchronous function, has to be awaited.
  static Future<bool> checkIfDeviceSecure() async {
    var result = await _channel.invokeMethod('checkIfDeviceSecure');
    if (result == true) {
      return true;
    } else {
      return false;
    }
  }

  /** SharedPref methods **/

  ///Writes provided data under provided key in shared preferences. Data is encrypted using AES.
  ///Returns true if data is successfully saved.
  static Future<bool> writeData(String key, String data) async {
    var result =
        await _channel.invokeMethod('writeData', {'key': key, 'data': data});
    if (result == true) {
      return true;
    } else {
      throw SharedPreferencesException(
          'Writing to shared preferences failed. Consider reopening or reinstalling the app.');
    }
  }

  ///Reads data saved under provided key from shared preferences.
  ///Returns data if it is successfully read.
  static Future<dynamic> readData(String key) async {
    var data = await _channel.invokeMethod('readData', {'key': key});
    if (data != false) {
      return data
          .toString()
          .substring(data.toString().indexOf(':') + 1, data.toString().length);
    } else {
      throw NoKeyInStorageException(
          'No such key found in phone storage. Consider saving it to storage before reading.');
    }
  }

  ///Deletes data saved under provided key from shared preferences. Returns true if data is successfully deleted.
  static Future<bool> deleteData(String key) async {
    var result = await _channel.invokeMethod('deleteData', {'key': key});
    if (result != false) {
      return true;
    } else {
      throw SharedPreferencesException(
          'Writing to shared preferences failed. Consider reopening or reinstalling the app.');
    }
  }

  ///Edits data under provided key in shared preferences. Data is encrypted using AES. Returns true if data is successfully saved.
  static Future<bool> editData(String key, String data) async {
    var result =
        await _channel.invokeMethod('editData', {'key': key, 'data': data});
    if (result == true) {
      return true;
    } else {
      throw SharedPreferencesException(
          'Writing to shared preferences failed. Consider reopening or reinstalling the app.');
    }
  }
}
