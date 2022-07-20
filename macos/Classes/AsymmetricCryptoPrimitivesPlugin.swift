import Cocoa
import FlutterMacOS
import CryptoKit
import Sodium
import Foundation


public class AsymmetricCryptoPrimitivesPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "asymmetric_crypto_primitives", binaryMessenger: registrar.messenger)
    let instance = AsymmetricCryptoPrimitivesPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "getPlatformVersion":
      result("macOS " + ProcessInfo.processInfo.operatingSystemVersionString)
    case "checkIfDeviceSecure":
        result(true)
        break
    case "establishForEd25519":
        print("Established")
        result(true)
        break
    case "readData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          var data =  UserDefaults.standard.string(forKey: key)
          if data == nil{
              result(false)
          }else{
              result(data)
          }
          break
      case "writeData":
          let args = call.arguments as? Dictionary<String, Any>
          let key = (args!["key"] as? String)!
          let data =  (args!["data"] as? String)!
          //let encryptedData = encryptData(dataToEncrypt: data)
          if data.isEmpty{
              result(false)
          }else{
              UserDefaults.standard.set(data, forKey: key)
              result(true)
          }
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
          //let encryptedData = encryptData(dataToEncrypt: data)
          if data.isEmpty{
              result(false)
          }else{
              UserDefaults.standard.set(data, forKey: key)
              result(true)
          }
          break
    default:
      result("Not Implemented")
    }
  }
    
    
}
