
A plugin for signing data using RSA or Ed25519. Enables the user to rotate the keys and clean unused ones. The package is based on [simple signing plugin](https://pub.dev/packages/simple_signing_plugin).

## Getting started
Using the RSA method for generating keys and data signing requires the screen lock to be enabled on the device. It can be easily checked by `checkIfDeviceSecure` method:
```dart
isDeviceSecure = await checkIfDeviceSecure(); //returns true if screen lock is set
```
Working with RSA algorithm without checking whether the screen lock is set may cause functions to throw the `DeviceNotSecuredException`.

To start working with the plugin it is necessary to initialize the `signer` object for Ed25519 or RSA method:
```dart
void main() async{  
  WidgetsFlutterBinding.ensureInitialized();  
 var signer = await THCLabSigningPlugin.establishForEd25519();  //or establishForRSA()
  runApp(MyApp(signer: signer,));  
}
```
Most of the plugin methods are available through `signer` object.

## Usage
#### Signing data
```dart
String strToSign = 'Sign me!';
signature = await signer.sign(strToSign);
```
#### Getting keys
```dart
String currentKey = '';  
String nextKey = '';
currentKey = await signer.getCurrentPubKey();  
nextKey = await signer.getNextPubKey();
```
#### Rotating keys
```dart
String currentKey = 'current key here!';  
String nextKey = 'next key here!';
await signer.rotateForEd25519();  
//To see the results of the rotation
currentKey = await signer.getCurrentPubKey();  
nextKey = await signer.getNextPubKey();
```
#### Getting the `signer`'s uique UUID
```dart
String uuid = '';
uuid = await signer.getUuid();
```
#### Getting a previously used `signer` object
```dart
void main() async{  
  WidgetsFlutterBinding.ensureInitialized();  
 var signer = await THCLabSigningPlugin.getEd25519SignerFromUuid('ecd886f1-1af6-4e62-a6b2-825e2b15ebd2');  //or getRSASignerFromUuid()
  runApp(MyApp(signer: signer,));  
}
```
This method will throw an `IncorrectUuidException` if no keys associated with the entered UUID were saved to the device.
#### Clean up
```dart
await THCLabSigningPlugin.cleanUp(signer);
```
Removes all the keys that were associated with this `signer` object.

## Data storing functions
```dart
//Writing data example
String _data = 'Data';
String _key = 'Key';
var result = await THCLabSigningPlugin.writeData(_key, _data); //returns true if everything goes fine. Can throw a SharedPreferencesException or DeviceNotSecuredException
```

```dart
//Reading data example
String _key = 'Key';
var result = await THCLabSigningPlugin.readData(_key); //returns data written under key if everything goes fine. Can throw a InvalidSignatureException, DeviceNotSecuredException or NoKeyInStorageException
```

```dart
//Deleting data example
String _key = 'Key';
var result = await THCLabSigningPlugin.deleteData(_key); //returns true if everything goes fine. Can throw a SharedPreferencesException or DeviceNotSecuredException
```

```dart
//Editing data example
String _data = 'Data';
String _key = 'Key';
var result = await THCLabSigningPlugin.editData(_key, _data); //returns true if everything goes fine. Can throw a SharedPreferencesException or DeviceNotSecuredException
```
