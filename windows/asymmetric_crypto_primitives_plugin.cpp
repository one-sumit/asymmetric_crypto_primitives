#define _CRT_SECURE_NO_WARNINGS
#include "asymmetric_crypto_primitives_plugin.h"

// This must be included before many other Windows headers.
#include <windows.h>

// For getPlatformVersion; remove unless needed for your plugin implementation.
#include <VersionHelpers.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <optional>
#include <sstream>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
//#include "sodium/crypto_sign.h"
//#include "sodium.h"

using namespace std;
using flutter::EncodableMap;
using flutter::EncodableValue;

namespace asymmetric_crypto_primitives {

// static
void AsymmetricCryptoPrimitivesPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  auto channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "asymmetric_crypto_primitives",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<AsymmetricCryptoPrimitivesPlugin>();

  channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto &call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

// Returns the data argument from |method_call| if it is present, otherwise
// returns an empty string.
std::string GetDataArgument(const flutter::MethodCall<>& method_call) {
  std::string data;
  const auto* arguments = std::get_if<EncodableMap>(method_call.arguments());
  if (arguments) {
    auto data_it = arguments->find(EncodableValue("data"));
    if (data_it != arguments->end()) {
      data = std::get<std::string>(data_it->second);
    }
  }
  return data;
}

// Returns the key argument from |method_call| if it is present, otherwise
// returns an empty string.
std::string GetKeyArgument(const flutter::MethodCall<>& method_call) {
  std::string key;
  const auto* arguments = std::get_if<EncodableMap>(method_call.arguments());
  if (arguments) {
    auto key_it = arguments->find(EncodableValue("key"));
    if (key_it != arguments->end()) {
      key = std::get<std::string>(key_it->second);
    }
  }
  return key;
}

// Returns the uuid argument from |method_call| if it is present, otherwise
// returns an empty string.
std::string GetUuidArgument(const flutter::MethodCall<>& method_call) {
  std::string uuid;
  const auto* arguments = std::get_if<EncodableMap>(method_call.arguments());
  if (arguments) {
    auto uuid_it = arguments->find(EncodableValue("uuid"));
    if (uuid_it != arguments->end()) {
      uuid = std::get<std::string>(uuid_it->second);
    }
  }
  return uuid;
}

void create_file(){
	std::ofstream outfile;
	char* appdata = getenv("APPDATA"); //get the path to folder Roaming AppData
	char* fileName = (char*) "\\passFile.txt"; //get the name of the .txt file

	//connect the path and the .txt file
	char * qq = (char*) malloc((strlen(appdata)+ strlen(fileName))*sizeof(char));
	strcpy(qq,appdata);
	strcat(qq,fileName);

	//open and close the file to create it
	outfile.open(qq, std::ios_base::app);
	outfile.close();
}

void write_data(char* key,const char* data){
	std::ofstream outfile;
	char* appdata = getenv("APPDATA"); //get the path to folder Roaming AppData
	char* fileName = (char*) "\\passFile.txt"; //get the name of the .txt file

	//connect the path and the .txt file
	char * qq = (char*) malloc((strlen(appdata)+ strlen(fileName))*sizeof(char));
	strcpy(qq,appdata);
	strcat(qq,fileName);

	//open the file to write data to it
	outfile.open(qq, std::ios_base::app);

	//connect the key, delimiter : and data into one string
	char* data_to_write = (char*) malloc((strlen(key)+strlen(":")+ strlen(data))*sizeof(char));
	strcpy(data_to_write, key);
	strcat(data_to_write, ":");
	strcat(data_to_write, data);

	//write to file
	if(outfile.is_open()){
		outfile << data_to_write <<  std::endl;
	}

	//close the file
	outfile.close();
}

bool is_file_exist(const char *fileName){
    std::ifstream infile(fileName);
    return infile.good();
}

bool check_uuid_exists(char* uuid){
    char* appdata = getenv("APPDATA"); //get the path to folder Roaming AppData
    	char* fileName = (char*) "\\passFile.txt"; //get the name of the .txt file

    	//connect the path and the .txt file
    	char * qq = (char*) malloc((strlen(appdata)+ strlen(fileName))*sizeof(char));
    	strcpy(qq,appdata);
    	strcat(qq,fileName);

    	//check if the file exists to avoid reading data before it is written
    	if(is_file_exist(qq)){
    		std::ifstream file(qq);
    		if (file.is_open()) {
    			std::string line;
    			//get each line of the .txt file
    			while (std::getline(file, line)) {
    				//create a string from each line
    				std::string myLine(line.c_str());
    				//if line contains the key (here uuid), return the data (here, key to sign)
    				if (myLine.find(uuid) != std::string::npos) {
    					return true;
    				}
    			}
    		//close the file
    		file.close();
    		}
    		return false;
    	}else{
    		return false;
    	}
}

std::string read_data(char* key){
	char* appdata = getenv("APPDATA"); //get the path to folder Roaming AppData
	char* fileName = (char*) "\\passFile.txt"; //get the name of the .txt file

	//connect the path and the .txt file
	char * qq = (char*) malloc((strlen(appdata)+ strlen(fileName))*sizeof(char));
	strcpy(qq,appdata);
	strcat(qq,fileName);

	//check if the file exists to avoid reading data before it is written
	if(is_file_exist(qq)){
		std::ifstream file(qq);
		if (file.is_open()) {
			std::string line;
			//get each line of the .txt file
			while (std::getline(file, line)) {
				//create a string from each line
				std::string myLine(line.c_str());
				//if line contains the key (here uuid), return the data (here, key to sign)
				if (myLine.find(key) != std::string::npos) {
					return myLine.substr(myLine.find(":")+1);
				}
			}
		//close the file
		file.close();
		}
		//if something goes wrong, return empty string
		return "";
	}else{
		//if something goes wrong, return empty string
		return "";
	}
}

void delete_data(char* key){
	char* appdata = getenv("APPDATA"); //get the path to folder Roaming AppData
	char* fileName = (char*) "\\passFile.txt"; //get the name of the .txt file
	char* fileNameTemp = (char*) "\\passFileTemp.txt"; //get the name of the temporary .txt file

	//connect the path and the .txt file
	char * qq = (char*) malloc((strlen(appdata)+ strlen(fileName))*sizeof(char));
	strcpy(qq,appdata);
	strcat(qq,fileName);

	//connect the path and the temporary .txt file
	char * qq2 = (char*) malloc((strlen(appdata)+ strlen(fileNameTemp))*sizeof(char));
	strcpy(qq2,appdata);
	strcat(qq2,fileNameTemp);

	//create streams to read from .txt and write to temp .txt
	std::ifstream file_to_read(qq);
	std::ofstream file_to_write(qq2);

	//while the .txt file has not reached its end
	if (!file_to_read.eof()) {
		std::string line;
		//get each line of the .txt file
		while (std::getline(file_to_read, line)) {
			//create a string from each line
	    	std::string myLine(line.c_str());
			//if line contains the key (here uuid), do nothing
	    	if (myLine.find(key) != std::string::npos) {
			}else{
				//else write the data to the temporary file
				file_to_write << myLine << std::endl;
			}
		}
	}

	//close both files
	file_to_read.close();
	file_to_write.close();
	//remove the original .txt file and rename the temp file to the original
	remove(qq);
	rename(qq2, qq);
}

void update_data(char* key, const char* data){
	char* appdata = getenv("APPDATA"); //get the path to folder Roaming AppData
	char* fileName = (char*) "\\passFile.txt"; //get the name of the .txt file
	char* fileNameTemp = (char*) "\\passFileTemp.txt"; //get the name of the temporary .txt file

	//connect the path and the .txt file
	char * qq = (char*) malloc((strlen(appdata)+ strlen(fileName))*sizeof(char));
	strcpy(qq,appdata);
	strcat(qq,fileName);

	//connect the path and the temporary .txt file
	char * qq2 = (char*) malloc((strlen(appdata)+ strlen(fileNameTemp))*sizeof(char));
	strcpy(qq2,appdata);
	strcat(qq2,fileNameTemp);

	//create streams to read from .txt and write to temp .txt
	std::ifstream file_to_read(qq);
	std::ofstream file_to_write(qq2);

	//while the .txt file has not reached its end
	if (!file_to_read.eof()) {
		std::string line;
		//get each line of the .txt file
		while (std::getline(file_to_read, line)) {
			//create a string from each line
	    	std::string myLine(line.c_str());
			//if line contains the key (here uuid)
	    	if (myLine.find(key) != std::string::npos) {
				//connect the uuid, delimiter and new data into one string
				char* data_to_write = (char*) malloc((strlen(key)+strlen(":")+ strlen(data))*sizeof(char));
				strcpy(data_to_write, key);
				strcat(data_to_write, ":");
				strcat(data_to_write, data);
				//write the new line to the temp file
				file_to_write << data_to_write << std::endl;
			}else{
				//else just write the original line to the temp file
				file_to_write << myLine << std::endl;
			}
		}
	}
	//close both files
	file_to_read.close();
	file_to_write.close();
	//remove the original .txt file and rename the temp file to the original
	remove(qq);
	rename(qq2, qq);
}

void cleanUp(char* uuid){
    bool isUuid = check_uuid_exists(uuid);
    if(isUuid){
        delete_data(uuid);
    }
}

/*
void generateEd25519Key(string uuid){
	unsigned char pk[crypto_sign_PUBLICKEYBYTES]; //create empty char array for public key
 	unsigned char sk[crypto_sign_SECRETKEYBYTES]; //create empty char array for secret key
 	crypto_sign_keypair(pk,sk); //generate the keypair
 	string sk_string = std::string((char *) sk,sizeof sk); //create string from binary secret key
	string pk_string = std::string((char *) pk,sizeof pk); //create string from binary public key

	//get the length of public key in base64
	size_t dst_pk_len = sodium_base64_encoded_len (crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE);
	//get the length of secret key in base64
	size_t dst_sk_len = sodium_base64_encoded_len (crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_URLSAFE);
	char* dst_pk = new char[dst_pk_len]; //create destination char array for public key
	char* dst_sk = new char[dst_sk_len]; //create destination char array for secret key

	//convert the public key from binary to base64 char array
	sodium_bin2base64(dst_pk, dst_pk_len, (unsigned char*) pk, crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE);
	//convert the secret key from binary to base64 char array
	sodium_bin2base64(dst_sk, dst_sk_len, (unsigned char*) sk, crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_URLSAFE);

	//write the public and private key in base64 to .txt file
	write_data((char*) (uuid + "_0_pub").c_str(),sodium_bin2base64(dst_pk, dst_pk_len, (unsigned char*) pk, crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE));
	write_data((char*) (uuid + "_0_priv").c_str(),sodium_bin2base64(dst_sk, dst_sk_len, (unsigned char*) sk, crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_URLSAFE));
}

void generateNextEd25519Key(string uuid){
	unsigned char pk[crypto_sign_PUBLICKEYBYTES]; //create empty char array for public key
 	unsigned char sk[crypto_sign_SECRETKEYBYTES]; //create empty char array for secret key
 	crypto_sign_keypair(pk,sk); //generate the keypair
 	string sk_string = std::string((char *) sk,sizeof sk); //create string from binary secret key
	string pk_string = std::string((char *) pk,sizeof pk); //create string from binary public key

	//get the length of public key in base64
	size_t dst_pk_len = sodium_base64_encoded_len (crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE);
	//get the length of secret key in base64
	size_t dst_sk_len = sodium_base64_encoded_len (crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_URLSAFE);
	char* dst_pk = new char[dst_pk_len]; //create destination char array for public key
	char* dst_sk = new char[dst_sk_len]; //create destination char array for secret key

	//write the public and private key in base64 to .txt file
	write_data((char*) (uuid + "_1_pub").c_str(),sodium_bin2base64(dst_pk, dst_pk_len, (unsigned char*) pk, crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE));
	write_data((char*) (uuid + "_1_priv").c_str(),sodium_bin2base64(dst_sk, dst_sk_len, (unsigned char*) sk, crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_URLSAFE));

}
*/

AsymmetricCryptoPrimitivesPlugin::AsymmetricCryptoPrimitivesPlugin() {}

AsymmetricCryptoPrimitivesPlugin::~AsymmetricCryptoPrimitivesPlugin() {}

void AsymmetricCryptoPrimitivesPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue> &method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  if(method_call.method_name().compare("writeData") == 0){
    std::string data = GetDataArgument(method_call);
    std::string key = GetKeyArgument(method_call);
    write_data((char*) key.c_str(), data.c_str());
    result->Success(flutter::EncodableValue(true));
  }else if(method_call.method_name().compare("readData") == 0){
    std::string key = GetKeyArgument(method_call);
    std::string data = read_data((char*) key.c_str());
    if(data.empty()){
      result->Success(flutter::EncodableValue(false));
    }else{
      result->Success(flutter::EncodableValue(data));
    }
  }else if(method_call.method_name().compare("deleteData") == 0){
    std::string key = GetKeyArgument(method_call);
    delete_data((char*) key.c_str());
    result->Success(flutter::EncodableValue(true));
  }else if(method_call.method_name().compare("editData") == 0){
    std::string data = GetDataArgument(method_call);
    std::string key = GetKeyArgument(method_call);
    update_data((char*) key.c_str(), data.c_str());
    result->Success(flutter::EncodableValue(true));
  }else if(method_call.method_name().compare("checkUuid") == 0){
      std::string uuid = GetUuidArgument(method_call);
      bool isUuid = check_uuid_exists((char*) uuid.c_str());
      result->Success(flutter::EncodableValue(isUuid));
  }else if(method_call.method_name().compare("cleanUp") == 0){
     std::string uuid = GetUuidArgument(method_call);
     cleanUp((char*) uuid.c_str());
     result->Success(flutter::EncodableValue(true));
   }
  else {
    result->NotImplemented();
  }
}




}  // namespace asymmetric_crypto_primitives
