
A plugin for signing data using RSA or Ed25519. Enables the user to rotate the keys and clean unused ones. It is based on [simple signing plugin](https://pub.dev/packages/simple_signing_plugin).

## Features
- Delivers EDDSA crypto primitive to Android and iOS, as they have no native support
- Will allow in the future to deliver a next gen asymmetric crypto algo to a device if it will not have the native support for the algorithm
- Allows the prerotation of keys, as it generates 2 key pairs by default.

## Getting started

### Android
Using the RSA method for generating keys and data signing requires the screen lock to be enabled on the device. It can be easily checked by `checkIfDeviceSecure` method:
```dart
isDeviceSecure = await checkIfDeviceSecure(); //returns true if screen lock is set
```
Working with RSA algorithm without checking whether the screen lock is set may cause functions to throw the `DeviceNotSecuredException`.

To start working with the plugin it is necessary to initialize the `signer` object for Ed25519 or RSA method:
```dart
void main() async{  
  WidgetsFlutterBinding.ensureInitialized();
  var isDeviceSecure = await AsymmetricCryptoPrimitives.checkIfDeviceSecure();
  if (isDeviceSecure) {
    var signer = await AsymmetricCryptoPrimitives.establishForRSA();
    runApp(MyApp(
      signer: signer,
    ));
  }
}
```
Most of the plugin methods are available through `signer` object.

### iOS
Currently the only supported algorithm is Ed25519. RSA is available, however the work is in progress and some functions do not work properly yet.

The default authentication method is PIN. Due to Apple's policy, in order to activate FaceID, it is necessary to edit your app's `Info.plist` file and add the following lines:
```plist
<key>NSFaceIDUsageDescription</key>
<string>iOS</string>
```
The rest of the setup would look like the one described for Android.

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
**Warning:** The rotation doesn't currently work for RSA algorithm. Work in progress.

#### Getting the `signer`'s uique UUID
```dart
String uuid = '';
uuid = await signer.getUuid();
```
#### Getting a previously used `signer` object
```dart
void main() async{
  WidgetsFlutterBinding.ensureInitialized();
  var signer = await AsymmetricCryptoPrimitives.getEd25519SignerFromUuid('ecd886f1-1af6-4e62-a6b2-825e2b15ebd2');  //or getRSASignerFromUuid()
  runApp(MyApp(signer: signer,));
}
```
This method will throw an `IncorrectUuidException` if no keys associated with the entered UUID were saved to the device.
#### Clean up
```dart
await AsymmetricCryptoPrimitives.cleanUp(signer);
```
Removes all the keys that were associated with this `signer` object.

## Data storing functions
```dart
//Writing data example
String _data = 'Data';
String _key = 'Key';
var result = await AsymmetricCryptoPrimitives.writeData(_key, _data); //returns true if everything goes fine. Can throw a SharedPreferencesException or DeviceNotSecuredException
```

```dart
//Reading data example
String _key = 'Key';
var result = await AsymmetricCryptoPrimitives.readData(_key); //returns data written under key if everything goes fine. Can throw a InvalidSignatureException, DeviceNotSecuredException or NoKeyInStorageException
```

```dart
//Deleting data example
String _key = 'Key';
var result = await AsymmetricCryptoPrimitives.deleteData(_key); //returns true if everything goes fine. Can throw a SharedPreferencesException or DeviceNotSecuredException
```

```dart
//Editing data example
String _data = 'Data';
String _key = 'Key';
var result = await AsymmetricCryptoPrimitives.editData(_key, _data); //returns true if everything goes fine. Can throw a SharedPreferencesException or DeviceNotSecuredException
```

