cmake_minimum_required(VERSION 3.15)
project("win32-webauthn" CXX)

include(ExternalProject)
include(FetchContent)

# Target Platfrom Configurations
if(NOT TARGET_PLATFORM)
  set(TARGET_PLATFORM "x64" CACHE STRING "Target architecture (x64, Win32, ARM64)")
  message(STATUS "No Platform specified, defaulting to: ${TARGET_PLATFORM}")
else()
  message(STATUS "Target Platform set to: ${TARGET_PLATFORM}")
endif()

# C++ Configurations
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /NODEFAULTLIB:MSVCRT /NODEFAULTLIB:LIBCMT")

# Build Library: libsodium
fetchcontent_declare(
  libsodium_source
  URL https://github.com/jedisct1/libsodium/releases/download/1.0.21-RELEASE/libsodium-1.0.21.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
fetchcontent_makeavailable(libsodium_source)
fetchcontent_getproperties(libsodium_source SOURCE_DIR SODIUM_SOURCE_DIR)
set(SODIUM_MSVC_SLN "${SODIUM_SOURCE_DIR}/builds/msvc/vs2026/libsodium.sln")
externalproject_add(
  libsodium_build
  SOURCE_DIR "${SODIUM_SOURCE_DIR}"
  CONFIGURE_COMMAND ""
  BUILD_COMMAND msbuild "${SODIUM_MSVC_SLN}" /p:Configuration=StaticRelease /p:Platform=${TARGET_PLATFORM} /t:libsodium
  INSTALL_COMMAND ""
  BUILD_IN_SOURCE 1
)
set(SODIUM_INCLUDE_DIR "${SODIUM_SOURCE_DIR}/src/libsodium/include")
set(SODIUM_LIB_PATH "${SODIUM_SOURCE_DIR}/bin/x64/Release/v145/static/libsodium.lib")

# Build Library: json
fetchcontent_declare(
  json_source
  URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
fetchcontent_makeavailable(json_source)

add_executable(
  ${PROJECT_NAME}
  "main.cpp"
)

target_include_directories(
  ${PROJECT_NAME} PRIVATE
  "${SODIUM_INCLUDE_DIR}"
)

target_compile_definitions(
  ${PROJECT_NAME} PRIVATE
  SECURITY_WIN32
  SODIUM_STATIC
)

target_link_libraries(
  ${PROJECT_NAME} PRIVATE
  User32.Lib
  Secur32.Lib
  AdvAPI32.Lib
  webauthn.lib
  crypt32.lib
  "${SODIUM_LIB_PATH}"
  nlohmann_json::nlohmann_json
)

add_dependencies(
  ${PROJECT_NAME}
  libsodium_build
)
