//
//  Generated file. Do not edit.
//

// clang-format off

#include "generated_plugin_registrant.h"

#include <asymmetric_crypto_primitives/asymmetric_crypto_primitives_plugin_c_api.h>
#include <local_auth_windows/local_auth_plugin.h>
#include <sodium_key_generator_plugin/sodium_key_generator_plugin_c_api.h>

void RegisterPlugins(flutter::PluginRegistry* registry) {
  AsymmetricCryptoPrimitivesPluginCApiRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("AsymmetricCryptoPrimitivesPluginCApi"));
  LocalAuthPluginRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("LocalAuthPlugin"));
  SodiumKeyGeneratorPluginCApiRegisterWithRegistrar(
      registry->GetRegistrarForPlugin("SodiumKeyGeneratorPluginCApi"));
}
