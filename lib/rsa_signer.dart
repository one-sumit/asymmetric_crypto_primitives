import 'package:flutter/services.dart';

class RSASigner{
  static const MethodChannel _channel = MethodChannel('ed25519_signing_plugin');
  String uuid;

  ///Constructor for RSA signer.
  RSASigner(this.uuid);


  ///Returns currently used public key for RSA signer.
  Future<String> getCurrentPubKey() async{
    var key = await _channel.invokeMethod("getRSAKey", {'alias': "${uuid}_0_rsa"});
    return key;
  }

  ///Returns second/backup public key for RSA signer.
  Future<String> getNextPubKey() async{
    var key = await _channel.invokeMethod("getRSAKey", {'alias': "${uuid}_1_rsa"});
    return key;
  }

  ///Returns the uuid of RSA signer.
  String getUuid(){
    return uuid;
  }

  ///Rotates the keys (the backup key becomes currently used and new key is generated as backup).
  Future<void> rotateForRSA() async{
    await _channel.invokeMethod("rotateForRSA", {'uuid' : uuid});
  }

  ///Signs provided message using RSA. Returns signature if successfully signed.
  Future<String> sign(String message) async{
    var signature = await _channel.invokeMethod("signRSA", {'uuid' : uuid, 'message' : message});
    return signature;
  }
}