# The Windows half of biometric_storage's Windows Hello support: a key-bound
# store whose key exists only after Windows Hello has signed (see
# windows_hello.cpp). The credential store itself is written from Dart
# (lib/src/biometric_storage_win32.dart).
cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME "tom_biometric_storage")
project(${PROJECT_NAME} LANGUAGES CXX)

cmake_policy(VERSION 3.14...3.25)

# This value is used when generating builds using this plugin, so it must
# not be changed.
set(PLUGIN_NAME "tom_biometric_storage_plugin")

add_library(${PLUGIN_NAME} SHARED
  "include/tom_biometric_storage/biometric_storage_plugin_c_api.h"
  "biometric_storage_plugin_c_api.cpp"
  "windows_hello.cpp"
  "windows_hello.h"
)

apply_standard_settings(${PLUGIN_NAME})

set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
# C++/WinRT (KeyCredentialManager) needs C++17. Every async call is waited on
# a worker thread, never on the platform thread.
target_compile_features(${PLUGIN_NAME} PRIVATE cxx_std_17)
target_compile_options(${PLUGIN_NAME} PRIVATE /EHsc)

target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin
  windowsapp bcrypt)

set(tom_biometric_storage_bundled_libraries
  ""
  PARENT_SCOPE
)
