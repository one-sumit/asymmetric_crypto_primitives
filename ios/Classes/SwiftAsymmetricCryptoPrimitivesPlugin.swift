import Flutter
import UIKit
import LocalAuthentication
import CryptoKit


@available(iOS 12.0, *)
public class SwiftAsymmetricCryptoPrimitivesPlugin: NSObject, FlutterPlugin {
  var IOS_AES_ALIAS = "9aac15df-4b0f-4f9d-a6b7-210aae2a1179"
    
    static public func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "asymmetric_crypto_primitives", binaryMessenger: registrar.messenger())
    let instance = SwiftAsymmetricCryptoPrimitivesPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
        if !instance.checkAESKeyExists(){
        makeAndStoreAESKey(name: instance.IOS_AES_ALIAS)
    }
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
      switch call.method {
      case "checkIfDeviceSecure":
          result(LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil))
          break
      case "readData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          var data =  UserDefaults.standard.string(forKey: key)
          print(data)
          if data == nil{
              result(false)
          }else{
              let tempdata = decryptData(dataToDecrypt: data!)
              data = tempdata
          }
          result(data)
          break
      case "writeData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          let data =  (args!["data"] as? String)!
          let encryptedData = encryptData(dataToEncrypt: data)
          UserDefaults.standard.set(encryptedData, forKey: key)
          result(true)
          break
      case "deleteData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          UserDefaults.standard.removeObject(forKey: key)
          result(true)
          break
      case "editData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          let data =  (args!["data"] as? String)!
          UserDefaults.standard.set(data, forKey: key)
          result(true)
          break
      default:
          result("Not implemented!")
          break
      }
  }
    
    public static func makeAndStoreAESKey(name: String, requiresBiometry: Bool = false) -> SecKey {
        let flags: SecAccessControlCreateFlags
        if #available(iOS 11.3, *) {
            flags = requiresBiometry ?
                [.privateKeyUsage, .biometryCurrentSet] : .privateKeyUsage
        } else {
            flags = requiresBiometry ?
                [.privateKeyUsage, .touchIDCurrentSet] : .privateKeyUsage
        }
        let access =
            SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                            flags,
                                            nil)!
        let tag = name.data(using: .utf8)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String     : 256,
            kSecAttrTokenID as String           : kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String       : true,
                kSecAttrApplicationTag as String    : tag,
                kSecAttrAccessControl as String     : access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)! //else {
            //throw error!.takeRetainedValue() as Error
        //}
        
        return privateKey
    }
    
    public func loadAESKey(name: String) -> SecKey? {
        let tag = name.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecReturnRef as String             : true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        return (item as! SecKey)
    }
    
//    func showSimpleAlert() {
//        let alert = UIAlertController(title: "Warning!", message: "Cipher data is null",         preferredStyle: UIAlertController.Style.alert)
//
//        alert.addAction(UIAlertAction(title: "Ok", style: UIAlertAction.Style.default, handler: { _ in
//            //Cancel Action
//        }))
//        alert.present(alert, animated: true, completion: nil)
//    }
    
    public func encryptData(dataToEncrypt: String) -> String{
        let key = loadAESKey(name: IOS_AES_ALIAS)
        let publicKey = SecKeyCopyPublicKey(key!)
        print(publicKey)
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(publicKey!, .encrypt, algorithm) else {
            print("The guard clause got here")
            return ""
        }
        var error: Unmanaged<CFError>?
        let clearTextData = dataToEncrypt.data(using: .utf8)!
        let cipherTextData = SecKeyCreateEncryptedData(publicKey!, algorithm,
                                                   clearTextData as CFData,
                                                   &error) as Data?
        guard cipherTextData != nil else {
            print("cipherTextData is nil")
            //showSimpleAlert()
            return ""
        }
        return cipherTextData!.base64EncodedString()
    }
    
    public func decryptData(dataToDecrypt: String) -> String{
        let privateKey = loadAESKey(name: IOS_AES_ALIAS)
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(privateKey!, .decrypt, algorithm) else {
            print("Algorithm not supported")
            return ""
        }

            // SecKeyCreateDecryptedData call is blocking when the used key
            // is protected by biometry authentication. If that's not the case,
            // dispatching to a background thread isn't necessary.
        

        var error: Unmanaged<CFError>?
        let clearTextData = SecKeyCreateDecryptedData(privateKey!,
                                                      algorithm,
                                                      Data.init(base64Encoded: dataToDecrypt)! as CFData,
                                                      &error) as Data?
        print(clearTextData)
        //DispatchQueue.main.async {
        guard clearTextData != nil else {
            print("clearTextData is nil")
            return ""
        }
        let clearText = String(decoding: clearTextData!, as: UTF8.self)
            // clearText is our decrypted string
        //}
        
        return String(decoding: clearTextData!, as: UTF8.self)
    }
    
    public func checkAESKeyExists() -> Bool{
        if(loadAESKey(name: IOS_AES_ALIAS) == nil){
            return false;
        }else{
            return true;
        }
    }
//
//    @available(iOS 15.0, *)
//    internal func generateAndStoreSymmetricKey(withKeychainTag: String) throws {
//      // Parameter:
//      let alias = withKeychainTag
//
//      let key = SymmetricKey(size: .bits256)
//
//      let addQuery:[CFString:Any] = [
//        kSecClass: kSecClassGenericPassword,
//        kSecAttrLabel: alias,
//        kSecAttrAccount: "Account \(alias)",
//        kSecAttrService: "Service \(alias)",
//        kSecReturnAttributes: true,
//      ]
//
//      var result: CFTypeRef?
//      let status = SecItemAdd(addQuery as CFDictionary, &result)
//    }
//
//    @available(iOS 15.0, *)
//    internal func retrieveSymmetricKey(withKeychainTag: String) throws -> SymmetricKey? {
//      // Parameter:
//      let alias = withKeychainTag
//
//      // Seek a generic password with the given account.
//      let query = [kSecClass: kSecClassGenericPassword,
//             kSecAttrAccount: "Account \(alias)",
//             kSecUseDataProtectionKeychain: true,
//             kSecReturnData: true] as [String: Any]
//
//      // Find and cast the result as data.
//      var item: CFTypeRef?
//      switch SecItemCopyMatching(query as CFDictionary, &item) {
//      case errSecSuccess:
//        guard let data = item as? Data else { throw Error.client("Fail to convert the key reference to Data.") }
//        return try SymmetricKey(rawRepresentation: data) // Convert back to a key.
//      case errSecItemNotFound: return nil
//      default: throw Error("Error in reading the key")
//      }
//    }
    
    
    
}

protocol GenericPasswordConvertible: CustomStringConvertible {
    /// Creates a key from a raw representation.
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes
    
    /// A raw representation of the key.
    var rawRepresentation: Data { get }
}

//@available(iOS 15.0, *)
//extension SymmetricKey: GenericPasswordConvertible {
//    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
//        self.init(data: data)
//    }
//
//    var rawRepresentation: Data {
//        return dataRepresentation  // Contiguous bytes repackaged as a Data instance.
//    }
//}
