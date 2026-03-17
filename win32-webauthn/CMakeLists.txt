cmake_minimum_required(VERSION 3.10)
project("Win32WebAuthn" CXX)

# WAJIB C++20 untuk fitur .dwVersion (Designated Initializers)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Pastikan nama target sama dengan yang di-link nanti
add_executable("win32-webauthn" "win32-webauthn.cpp")

# Link library sistem
target_link_libraries("win32-webauthn" PRIVATE
  webauthn.lib
  user32.lib
)
