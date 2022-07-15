import Flutter
import UIKit
import LocalAuthentication
import CryptoKit


public class SwiftAsymmetricCryptoPrimitivesPlugin: NSObject, FlutterPlugin {
  let IOS_AES_ALIAS = "9aac15df-4b0f-4f9d-a6b7-210aae2a1179"
    
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "asymmetric_crypto_primitives", binaryMessenger: registrar.messenger())
    let instance = SwiftAsymmetricCryptoPrimitivesPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
      switch call.method {
      case "checkIfDeviceSecure":
          result(LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil))
          break
      case "readData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          let data =  UserDefaults.standard.string(forKey: key)
          if data == nil{
              result(false)
          }
          result(data)
          break
      case "writeData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          let data =  (args!["data"] as? String)!
          UserDefaults.standard.set(data, forKey: key)
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
          result("iOS " + UIDevice.current.systemVersion)
          break
      }
  }
    
//    public func checkAESKeyExists() -> Bool{
//        if(retrieveSymmetricKey(withKeychainTag: IOS_AES_ALIAS) = nil){
//            return false;
//        }else{
//            return true;
//        }
//    }
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
