///An exception thrown when the sodium library could not have been initialized
class InitializationFailedException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  InitializationFailedException(this.cause);
  @override
  String toString() => "InitializationFailedException: $cause";
}

///An exception thrown when the base64 decoding of the key from the database has failed
class KeyDecodingFailedException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  KeyDecodingFailedException(this.cause);
  @override
  String toString() => "KeyDecodingFailedException: $cause";
}

///An exception thrown when the transformation from base64 string to sodium SecretKey has failed.
class KeyTransformingFailedException implements Exception {
  ///The description for the exception.
  String cause;

  ///Exception constructor containing the description for the exception.
  KeyTransformingFailedException(this.cause);
  @override
  String toString() => "KeyTransformingFailedException: $cause";
}
