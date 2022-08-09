# The Flutter tooling requires that developers have a version of Visual Studio
# installed that includes CMake 3.14 or later. You should not increase this
# version, as doing so will cause the plugin to fail to compile for some
# customers of the plugin.
cmake_minimum_required(VERSION 3.14)

# Project-level configuration.
set(PROJECT_NAME "asymmetric_crypto_primitives")
project(${PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -lsodium")

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "asymmetric_crypto_primitives_plugin")

# Any new source files that you add to the plugin should be added here.
list(APPEND PLUGIN_SOURCES
  "asymmetric_crypto_primitives_plugin.cpp"
  "asymmetric_crypto_primitives_plugin.h"
)

# Define the plugin library target. Its name must not be changed (see comment
# on PLUGIN_NAME above).
add_library(${PLUGIN_NAME} SHARED
  "include/asymmetric_crypto_primitives/asymmetric_crypto_primitives_plugin_c_api.h"
  "asymmetric_crypto_primitives_plugin_c_api.cpp"
  ${PLUGIN_SOURCES}
  )
add_library(sodium SHARED IMPORTED)

# Apply a standard set of build settings that are configured in the
# application-level CMakeLists.txt. This can be removed for plugins that want
# full control over build settings.
apply_standard_settings(${PLUGIN_NAME})

# Symbols are hidden by default to reduce the chance of accidental conflicts
# between plugins. This should not be removed; any symbols that should be
# exported should be explicitly exported with the FLUTTER_PLUGIN_EXPORT macro.
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  IMPORTED_IMPLIB "${CMAKE_CURRENT_SOURCE_DIR}/libsodium.lib"
  IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/libsodium.dll"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/sodium"
  )
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

# Source include directories and library dependencies. Add any plugin-specific
# dependencies here.
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/sodium"
  )
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin
"${CMAKE_CURRENT_SOURCE_DIR}/libsodium.lib" PRIVATE flutter flutter_wrapper_plugin
)

# include(Findsodium.cmake)


# List of absolute paths to libraries that should be bundled with the plugin.
# This list could contain prebuilt libraries, or libraries created by an
# external build triggered from this build file.
set(asymmetric_crypto_primitives_bundled_libraries
  "${CMAKE_CURRENT_SOURCE_DIR}/libsodium.lib"
  PARENT_SCOPE
)
