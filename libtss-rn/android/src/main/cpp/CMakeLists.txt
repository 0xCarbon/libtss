cmake_minimum_required(VERSION 3.18.1)
project(libtss-jni)

if(NOT DEFINED ANDROID_ABI)
    message(FATAL_ERROR "ANDROID_ABI is not defined")
endif()

if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(LIBTSS_FFI_TARGET "aarch64-linux-android")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(LIBTSS_FFI_TARGET "x86_64-linux-android")
else()
    message(FATAL_ERROR "Unsupported Android ABI for libtss-rn: ${ANDROID_ABI}")
endif()

# --- Bundled path (npm-published layout) ---
get_filename_component(LIBTSS_ANDROID_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../" ABSOLUTE)
set(LIBTSS_FFI_BUNDLED "${LIBTSS_ANDROID_DIR}/libs/${LIBTSS_FFI_TARGET}/liblibtss_ffi.a")

# --- Workspace path (local development) ---
get_filename_component(LIBTSS_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../" ABSOLUTE)
set(LIBTSS_FFI_WORKSPACE "${LIBTSS_REPO_ROOT}/target/${LIBTSS_FFI_TARGET}/release/liblibtss_ffi.a")

if(EXISTS "${LIBTSS_FFI_BUNDLED}")
    set(LIBTSS_FFI_ARCHIVE "${LIBTSS_FFI_BUNDLED}")
    set(LIBTSS_FFI_INCLUDE_DIR "${LIBTSS_ANDROID_DIR}/include")
elseif(EXISTS "${LIBTSS_FFI_WORKSPACE}")
    set(LIBTSS_FFI_ARCHIVE "${LIBTSS_FFI_WORKSPACE}")
    set(LIBTSS_FFI_INCLUDE_DIR "${LIBTSS_REPO_ROOT}/libtss-ffi")
else()
    message(FATAL_ERROR
        "Missing prebuilt liblibtss_ffi.a for ${ANDROID_ABI}.\n"
        "  Bundled:   ${LIBTSS_FFI_BUNDLED}\n"
        "  Workspace: ${LIBTSS_FFI_WORKSPACE}\n"
        "Build it with: cargo ndk --target ${LIBTSS_FFI_TARGET} --platform 21 -- build --release -p libtss-ffi")
endif()

add_library(libtss_ffi STATIC IMPORTED)
set_target_properties(libtss_ffi PROPERTIES IMPORTED_LOCATION "${LIBTSS_FFI_ARCHIVE}")

add_library(libtss-jni SHARED libtss-jni.cpp)
target_include_directories(libtss-jni PRIVATE "${LIBTSS_FFI_INCLUDE_DIR}")

find_library(log-lib log)

target_link_libraries(libtss-jni libtss_ffi ${log-lib})
