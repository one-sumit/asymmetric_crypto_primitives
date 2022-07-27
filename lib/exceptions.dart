///An exception thrown when there is no entry under such key in keystore.
class NoKeyInStorageException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  NoKeyInStorageException(this.cause);
  @override
  String toString() => "NoKeyInStorageException: $cause";
}

///An exception thrown when the signer created from UUID is incorrect and there are no keys
///containing provided uuid
class IncorrectUuidException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  IncorrectUuidException(this.cause);
  @override
  String toString() => "IncorrectUuidException: $cause";
}

///An exception thrown when there is no secure screen lock set on the device.
class DeviceNotSecuredException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  DeviceNotSecuredException(this.cause);
  @override
  String toString() => "DeviceNotSecuredException: $cause";
}

///An exception thrown when the data signature is invalid.
class InvalidSignatureException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  InvalidSignatureException(this.cause);
  @override
  String toString() => "InvalidSignatureException: $cause";
}

///An exception thrown when there is an error in shared preferences.
class SharedPreferencesException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  SharedPreferencesException(this.cause);
  @override
  String toString() => "SharedPreferencesException: $cause";
}

///An exception thrown when signing the message has failed
class SigningFailureException implements Exception{
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  SigningFailureException(this.cause);
  @override
  String toString() => "SigningFailureException: $cause";
}
