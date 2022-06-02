package com.thclab.asymmetric_crypto_primitives

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.Toast
import androidx.annotation.NonNull
import androidx.annotation.RequiresApi
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.Sign
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.PluginRegistry
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.security.auth.x500.X500Principal
import kotlin.properties.Delegates

/** AsymmetricCryptoPrimitivesPlugin */
class AsymmetricCryptoPrimitivesPlugin: FlutterPlugin, MethodCallHandler, ActivityAware, PluginRegistry.ActivityResultListener  {
  /// The MethodChannel that will the communication between Flutter and native Android
  ///
  /// This local reference serves to register the plugin with the Flutter Engine and unregister it
  /// when the Flutter Engine is detached from the Activity
  private lateinit var channel : MethodChannel
  private lateinit var context: Context
  private lateinit var activity: Activity
  private lateinit var keyPairRSA: java.security.KeyPair
  var lazySodium = LazySodiumAndroid(SodiumAndroid())
  private lateinit var keyguardManager: KeyguardManager
  private var isDeviceSecure by Delegates.notNull<Boolean>()
  private var dataToSign: String = ""
  private var dataSignature: String = ""
  private lateinit var pendingResult: Result
  private lateinit var signatureResult: String
  private lateinit var resultUuid : String
  private lateinit var mode: String
  private lateinit var EdMessage: String
  private lateinit var EdPubKey: String
  private lateinit var EdPrivKey: String

  override fun onAttachedToEngine(@NonNull flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "thclab_signing_plugin")
    channel.setMethodCallHandler(this)
    context = flutterPluginBinding.applicationContext
    keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    checkIfDeviceSecure()

    if(!checkAESKeyExists()){
      createAESKey()
    }
  }


  @RequiresApi(Build.VERSION_CODES.LOLLIPOP)
  override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
    if(call.method == "signEd25519"){
      mode = "Ed25519"
      val message = call.argument<String>("message")
      val uuid = call.argument<String>("uuid")
      var pub = readData("${uuid}_0_pub")
      var priv = readData("${uuid}_0_priv")
      if (message != null) {
        EdMessage = message
      }
      EdPubKey = pub as String
      EdPrivKey = priv as String
      this.pendingResult = result
      if (uuid != null) {
        this.resultUuid = uuid
      }
      val intent: Intent? = keyguardManager.createConfirmDeviceCredentialIntent("Keystore Sign And Verify",
        "In order to sign the data you need to confirm your identity. Please enter your pin/pattern or scan your fingerprint")
      if (intent != null) {
        activity.startActivityForResult(intent, REQUEST_CODE_FOR_CREDENTIALS)
      }
//      var kp = KeyPair(Key.fromBase64String(pub as String?), Key.fromBase64String(priv as String?))
//      var signature = message?.let { signEd25519(kp, it, lazySodium) }
//      result.success(signature)
    }else if(call.method == "signRSA"){
      mode = "RSA"
      val uuid = call.argument<String>("uuid")
      if (uuid != null) {
        this.resultUuid = uuid
      }
      this.pendingResult = result
      val data = call.argument<String>("message")
      if (data != null) {
        dataToSign = data
        val intent: Intent? = keyguardManager.createConfirmDeviceCredentialIntent("Keystore Sign And Verify",
          "In order to sign the data you need to confirm your identity. Please enter your pin/pattern or scan your fingerprint")
        if (intent != null) {
          activity.startActivityForResult(intent, REQUEST_CODE_FOR_CREDENTIALS)
        }
      }else{
        result.error("UNAVAILABLE", "Data cannot be null!", null)
      }
    }else if(call.method == "getRSAKey"){
      val alias = call.argument<String>("alias")
      val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
      }
      val publicKey: PublicKey? = keyStore.getCertificate(alias)?.publicKey
      if (publicKey != null) {
        result.success(Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP))
      }else{
        result.success(false)
      }
    }
    else if(call.method == "checkIfDeviceSecure"){
      val getResult = checkIfDeviceSecure()
      if (getResult){
        result.success(true)
      }else{
        result.success(false)
      }
    }else if (call.method == "writeData"){
      val key = call.argument<String>("key")
      val dataToWrite = call.argument<String>("data")
      if (key != null && dataToWrite != null) {
        writeData(key, dataToWrite)
        result.success(true)
      }else{
        result.success(false)
      }
    } else if (call.method == "readData"){
      val key = call.argument<String>("key")
      if(key != null){
        val userData = readData(key)
        if(userData != false){
          result.success(userData)
        }else{
          result.success(false)
        }
      }
    }
    else if (call.method == "deleteData"){
      val key = call.argument<String>("key")
      if (key != null) {
        deleteData(key)
        result.success(true)
      }else{
        result.success(false)
      }
    }
    else if (call.method == "editData"){
      val key = call.argument<String>("key")
      val dataToWrite = call.argument<String>("data")
      if (key != null && dataToWrite != null) {
        editData(key, dataToWrite)
        result.success(true)
      }else{
        result.success(false)
      }
    }else if(call.method == "establishForEd25519"){
      val uuid = call.argument<String>("uuid")
      if (uuid != null) {
        try {
          createEd25519Key(uuid)
          createSecondEd25519Key(uuid)
          result.success(true)
        }catch (e: Exception){
          result.success(false)
        }
      }
    }else if(call.method == "establishForRSA"){
      val uuid = call.argument<String>("uuid")
      if (uuid != null) {
        try {
          createRSAKey(uuid)
          createNextRSAKey(uuid)
          result.success(true)
        }catch (e: Exception){
          result.success(false)
        }
      }
    }else if(call.method == "rotateForEd25519"){
      val uuid = call.argument<String>("uuid")
      if (uuid != null) {
        try {
          var pubKey1 = readData("${uuid}_1_pub")
          var privKey1 = readData("${uuid}_1_priv")
          writeData("${uuid}_0_pub", pubKey1 as String)
          writeData("${uuid}_0_priv", privKey1 as String)
          createSecondEd25519Key(uuid)
          result.success(true)
        }catch (e: Exception){
          result.success(false)
        }
      }
    }else if(call.method == "rotateForRSA"){
      val uuid = call.argument<String>("uuid")
      if (uuid != null) {
        try {
          val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
          }
          val privateKey = keyStore.getKey("${uuid}_1_rsa", null)
          val publicKey = if (privateKey != null) keyStore.getCertificate("${uuid}_1_rsa") else null
          keyStore.setKeyEntry("${uuid}_0_rsa", privateKey,  null, arrayOf(publicKey))
          createNextRSAKey(uuid)
          val privateKey2 = keyStore.getKey("${uuid}_1_rsa", null)
          result.success(true)
        }catch (e: Exception){
          result.success(false)
        }
      }
    }else if(call.method == "cleanUp"){
      val uuid = call.argument<String>("uuid")
      try{
        if (uuid != null) {
          cleanUp(uuid)
          result.success(true)
        }
      }catch (e: Exception){
        result.success(false)
      }
    }else if(call.method == "checkUuid"){
      val uuid = call.argument<String>("uuid")
      var resulted = checkUuid(uuid!!)
      result.success(resulted)
    }
    else {
      result.notImplemented()
    }
  }

  override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

  @RequiresApi(Build.VERSION_CODES.M)
  private fun checkIfDeviceSecure() : Boolean{
    return if (!keyguardManager.isDeviceSecure) {
      Toast.makeText(context, "Secure lock screen hasn't set up.", Toast.LENGTH_LONG).show()
      isDeviceSecure = false
      false
    }else{
      isDeviceSecure = true
      true
    }
  }

  fun checkUuid(uuid: String) : Boolean{
    val prefs = activity.getPreferences(Context.MODE_PRIVATE)
    val keys: Map<String, *> = prefs.all
    for ((key, value) in keys) {
      if(key.contains(uuid!!)){
        return true
      }
    }
    val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
      load(null)
    }
    var containsKey0 = keyStore.isKeyEntry("${uuid}_0_rsa")
    var containsKey1 = keyStore.isKeyEntry("${uuid}_1_rsa")
    if(containsKey0 && containsKey1){
      return true
    }
    return false
  }


  /** Ed25519 functions */
  fun signEd25519(keyPair: KeyPair, text: String, lazySodium: LazySodiumAndroid): String? {
    val messageBytes: ByteArray = lazySodium.bytes(text)
    val signedMessage: ByteArray = lazySodium.randomBytesBuf(Sign.BYTES)
    val res: String? = lazySodium.cryptoSignDetached(
      text, keyPair.secretKey
    )
    if (res != null) {
    }
    return res
  }

  fun getPublicKey(keyPair: KeyPair) = Base64.encodeToString(keyPair.publicKey.asBytes, Base64.NO_WRAP)
  fun getPrivateKey(keyPair: KeyPair) = Base64.encodeToString(keyPair.secretKey.asBytes, Base64.NO_WRAP)

  /** Shared Preferences functions */
  fun writeData(key: String, data: String){
    try{
      val encryptedData = encrypt(data)
      val sharedPref = activity.getPreferences(Context.MODE_PRIVATE) ?: return
      with (sharedPref.edit()) {
        putString(key, encryptedData)
        apply()
      }
    }catch (e: Exception){
      Toast.makeText(context, "Something went wrong, try again!", Toast.LENGTH_SHORT).show()
    }
  }

  private fun readData(key: String): Any {
    val sharedPref = activity.getPreferences(Context.MODE_PRIVATE)
    val textToRead : String? = sharedPref.getString(key, null)
    if(textToRead.isNullOrEmpty()){
      return false
    }else{
      val userData = decrypt(textToRead)
      if(userData != null){
        return userData
      }
      return false
    }
  }

  private fun deleteData(key: String){
    try{
      val sharedPref = activity.getPreferences(Context.MODE_PRIVATE) ?: return
      with (sharedPref.edit()) {
        remove(key)
        apply()
      }
    }catch (e: Exception){
      Toast.makeText(context, "Something went wrong, try again!", Toast.LENGTH_SHORT).show()
    }
  }

  private fun editData(key: String, data: String){
    try{
      val encryptedStringConcat = encrypt(data)
      val sharedPref = activity.getPreferences(Context.MODE_PRIVATE) ?: return
      with (sharedPref.edit()) {
        putString(key, encryptedStringConcat)
        apply()
      }
    }catch (e: Exception){
      Toast.makeText(context, "Something went wrong, try again!", Toast.LENGTH_SHORT).show()
    }
  }

  /** Key generation functions */
  //FUNCTION TO CREATE AES KEY FOR ENCRYPTION AND DECRYPTION
  private fun createAESKey() {
    val keyGenerator = KeyGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE
    )
    keyGenerator.init(
      KeyGenParameterSpec.Builder(
        ANDROID_AES_ALIAS,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .build()
    )
    keyGenerator.generateKey()
  }

  //FUNCTION TO CHECK IF KEY FOR ENCRYPTION AND DECRYPTION EXISTS
  private fun checkAESKeyExists() :Boolean{
    val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
      load(null)
    }
    //We get the aes key from the keystore if they exists
    val secretKey = keyStore.getKey(ANDROID_AES_ALIAS, null) as SecretKey?
    return secretKey != null
  }

  private fun createEd25519Key(uuid: String){
    val keyPair by lazy {
      lazySodium.cryptoSignKeypair().apply {
        val newKeyPair = this
      }
    }
    var pub = getPublicKey(keyPair)
    writeData("${uuid}_0_pub", pub)
    var priv = getPrivateKey(keyPair)
    writeData("${uuid}_0_priv", priv)
  }

  private fun createSecondEd25519Key(uuid: String){
    val keyPair by lazy {
      lazySodium.cryptoSignKeypair().apply {
        val newKeyPair = this
      }
    }
    var pub = getPublicKey(keyPair)
    writeData("${uuid}_1_pub", pub)
    var priv = getPrivateKey(keyPair)
    writeData("${uuid}_1_priv", priv)
  }


  //FUNCTION TO GENERATE KEY TO SIGN/VERIFY DATA
  private fun createRSAKey(uuid: String) {
    if(isDeviceSecure){
      val startDate = GregorianCalendar()
      val endDate = GregorianCalendar()
      endDate.add(Calendar.YEAR, 1)

      val keyPairGenerator: java.security.KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)

      val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder("${uuid}_0_rsa",
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).run {
        setCertificateSerialNumber(BigInteger.valueOf(777))
        setCertificateSubject(X500Principal("CN=${uuid}_0_rsa"))
        setDigests(KeyProperties.DIGEST_SHA256)
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setCertificateNotBefore(startDate.time)
        setCertificateNotAfter(endDate.time)
        setUserAuthenticationRequired(true)
        setUserAuthenticationValidityDurationSeconds(10)
        build()
      }
      keyPairGenerator.initialize(parameterSpec)
      keyPairRSA = keyPairGenerator.genKeyPair()
    }
  }

  private fun createNextRSAKey(uuid: String) {
    if(isDeviceSecure){
      val startDate = GregorianCalendar()
      val endDate = GregorianCalendar()
      endDate.add(Calendar.YEAR, 1)

      val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)

      val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder("${uuid}_1_rsa",
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).run {
        setCertificateSerialNumber(BigInteger.valueOf(777))
        setCertificateSubject(X500Principal("CN=${uuid}_1_rsa"))
        setDigests(KeyProperties.DIGEST_SHA256)
        setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
        setCertificateNotBefore(startDate.time)
        setCertificateNotAfter(endDate.time)
        setUserAuthenticationRequired(true)
        setUserAuthenticationValidityDurationSeconds(10)
        build()
      }
      keyPairGenerator.initialize(parameterSpec)
      keyPairRSA = keyPairGenerator.genKeyPair()
    }
  }

  fun cleanUp(uuid: String){
    val prefs = activity.getPreferences(Context.MODE_PRIVATE)
    val keys: Map<String, *> = prefs.all
    for ((key, value) in keys) {
      if(key.contains(uuid)){
        deleteData(key)
      }
    }
    val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
      load(null)
    }
    var containsKey0 = keyStore.isKeyEntry("${uuid}_0_rsa")
    var containsKey1 = keyStore.isKeyEntry("${uuid}_1_rsa")
    if(containsKey0){
      keyStore.deleteEntry("${uuid}_0_rsa")
    }
    if(containsKey1){
      keyStore.deleteEntry("${uuid}_1_rsa")
    }
  }


  /** Encryption/decryption functions */
  //FUNCTION TO ENCRYPT DATA WHEN WRITTEN INTO STORAGE
  private fun encrypt(strToEncrypt: String) :  String? {
    try
    {
      val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
      }
      //We get the aes key from the keystore if they exists
      val secretKey = keyStore.getKey(ANDROID_AES_ALIAS, null) as SecretKey
      var result = ""
      val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
      cipher.init(Cipher.ENCRYPT_MODE, secretKey)
      val iv = cipher.iv
      val ivString = Base64.encodeToString(iv, Base64.DEFAULT)
      result += Base64.encodeToString(cipher.doFinal(strToEncrypt.toByteArray(Charsets.UTF_8)), Base64.DEFAULT)
      result += IV_SEPARATOR + ivString
      return result
    }
    catch (e: Exception) {
    }
    return null
  }

  //FUNCTION TO DECRYPT DATA WHEN READ FROM STORAGE
  private fun decrypt(strToDecrypt : String) : String? {
    try{
      val split = strToDecrypt.split(IV_SEPARATOR.toRegex())
      val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
      }
      val ivString = split[1]
      val encodedData = split[0]
      //We get the aes key from the keystore if they exists
      val secretKey = keyStore.getKey(ANDROID_AES_ALIAS, null) as SecretKey
      val ivSpec = IvParameterSpec(Base64.decode(ivString, Base64.DEFAULT))
      val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")

      cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
      return  String(cipher.doFinal(Base64.decode(encodedData, Base64.DEFAULT)))
    }catch (e: Exception) {
    }
    return null
  }

  /** Activity functions */
  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    activity = binding.activity
    binding.addActivityResultListener(this)
  }

  override fun onDetachedFromActivityForConfigChanges() {
    TODO("Not yet implemented")
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    TODO("Not yet implemented")
  }

  override fun onDetachedFromActivity() {
    TODO("Not yet implemented")
  }

  //FUNCTION TO CATCH AUTHENTICATION RESULT
  override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
    if (requestCode == REQUEST_CODE_FOR_CREDENTIALS) {
      if (resultCode == Activity.RESULT_OK) {
        if(mode == "Ed25519"){
          var kp = KeyPair(Key.fromBase64String(EdPubKey as String?), Key.fromBase64String(EdPrivKey as String?))
          var signature = EdMessage?.let { signEd25519(kp, it, lazySodium) }
          pendingResult.success(signature)
          return true
        }else if(mode == "RSA"){
          val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
          }
          val privateKey: PrivateKey = keyStore.getKey("${resultUuid}_0_rsa", null) as PrivateKey
          val signature: ByteArray? = Signature.getInstance("SHA256withRSA").run {
            initSign(privateKey)
            update(dataToSign.toByteArray())
            sign()
          }
          if (signature != null) {
            signatureResult = Base64.encodeToString(signature, Base64.DEFAULT)
            dataSignature = signatureResult
            val stringConcat = "$signatureResult:$dataToSign"
            pendingResult.success(stringConcat)
          }
          return true
        }else{
          Toast.makeText(context, "Authentication failed.", Toast.LENGTH_SHORT).show()
          pendingResult.success(false)
          activity.finish()
          return false
        }
      } else {
        Toast.makeText(context, "Authentication failed.", Toast.LENGTH_SHORT).show()
        pendingResult.success(false)
        activity.finish()
        return false
      }
    }
    else{
      return false
    }
  }
}

//KEYSTORE ALIAS
private const val ANDROID_KEYSTORE = "AndroidKeyStore"
//ENCRYPT/DECRYPT KEY ALIAS
private const val ANDROID_AES_ALIAS = "da1500b3-1671-4abd-a12d-358dbd4561a2"
//IV STRING SEPARATOR
private const val IV_SEPARATOR = ";"
//ALIAS FOR SETTING CHOSEN ALGORITHM
private const val ALGORITHM_ALIAS = "355114e2-35d0-4e55-b764-7cbdf949ce8b"
//REQUEST CODE FOR AUTHENTICATION SCREEN
const val REQUEST_CODE_FOR_CREDENTIALS = 1
