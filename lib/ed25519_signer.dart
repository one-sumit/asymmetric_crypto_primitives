import 'package:flutter/services.dart';

class Ed25519Signer{
  static const MethodChannel _channel = MethodChannel('ed25519_signing_plugin');
  String uuid;

  ///Constructor for Ed25519 signer.
  Ed25519Signer(this.uuid);


  ///Returns currently used public key for Ed25519 signer.
  Future<String> getCurrentPubKey() async{
    var key = await _channel.invokeMethod("readData", {'key': "${uuid}_0_pub"});
    return key;
  }

  ///Returns second/backup public key for Ed25519 signer.
  Future<String> getNextPubKey() async{
    var key = await _channel.invokeMethod("readData", {'key': "${uuid}_1_pub"});
    return key;
  }

  ///Returns the uuid of Ed25519 signer.
  String getUuid(){
    return uuid.toString();
  }

  ///Rotates the keys (the backup key becomes currently used and new key is generated as backup).
  Future<void> rotateForEd25519() async{
    await _channel.invokeMethod("rotateForEd25519", {'uuid' : uuid});
  }

  ///Signs provided message using Ed25519. Returns signature if successfully signed.
  Future<String> sign(String message) async{
    var signature = await _channel.invokeMethod("signEd25519", {'uuid' : uuid, 'message' : message});
    return signature;
  }

}