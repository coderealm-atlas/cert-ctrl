# Windows Build Status

## Date: October 6, 2025

## Fixed Issues ✅

### 1. Platform-Specific Headers
- **Issue**: `unistd.h` not available on Windows
- **Fix**: Added `#ifdef _WIN32` guards and included `winsock2.h` for Windows
- **Files**: `src/device_fingerprint.cpp`

### 2. Filesystem Path Conversions
- **Issue**: `std::filesystem::path::c_str()` returns `wchar_t*` on Windows
- **Fix**: Changed to `.generic_string().c_str()` for cross-platform UTF-8 strings
- **Files**: 
  - `external/http_client/include/api_handler_base.hpp`
  - `src/file_compress_util.cpp` (multiple locations)
  - `external/http_client/include/simple_data.hpp`

### 3. Base64 Function Signatures
- **Issue**: `base64_encode`/`base64_decode` parameter mismatches
- **Fix**: Corrected calls to use `(unsigned char*, size_t, bool)` signature
- **Files**: `src/openssl_raii.cpp`, `include/util/string_util.hpp`

### 4. C++20 Feature Compatibility
- **Issue**: MSVC missing some C++20 features (`std::string::starts_with`, `ends_with`)
- **Fix**: Implemented C++17 compatible versions using `rfind` and `substr`
- **Files**: `external/http_client/include/simple_data.hpp`

### 5. Missing Headers
- **Issue**: Missing `<sstream>` include
- **Fix**: Added `#include <sstream>`
- **Files**: `external/http_client/include/simple_data.hpp`

### 6. std::format Issues
- **Issue**: Const eval errors with `std::format`
- **Fix**: Replaced with string concatenation
- **Files**: `external/http_client/include/simple_data.hpp`

### 7. gethostname Function
- **Issue**: Function not available without proper headers on Windows
- **Fix**: Added `winsock2.h` include and linked `ws2_32.lib`
- **Files**: `src/device_fingerprint.cpp`

### 8. UTF-8 Encoding
- **Issue**: MSBuild output showing malformed characters
- **Fix**: Created `.vscode/settings.json` with comprehensive UTF-8 configuration
  - Added `MSBUILDCONSOLEENCODING=UTF-8`
  - Added `VSLANG=1033` (English)
  - Added `LANG=en_US.UTF-8` environment variables

## Remaining Issues ❌

### 1. Runtime Library Mismatch (CRITICAL)
- **Issue**: vcpkg libraries built with `/MTd` (static runtime), but project uses `/MDd` (dynamic runtime)
- **Error**: `error LNK2038: detected mismatch for 'RuntimeLibrary'`
- **Solution**: Need to ensure consistent runtime library linkage
- **Options**:
  1. Rebuild vcpkg packages with `/MDd` (dynamic runtime)
  2. Change project to use `/MTd` (static runtime) - currently configured but not working
  3. Use vcpkg dynamic triplet: `x64-windows-dynamic`

### 2. Object File Size Limit
- **Issue**: Files exceed COFF object format section limit
- **Error**: `error C1128: number of sections exceeded object file format limit: compile with /bigobj`
- **Affected Files**:
  - `src/cert_ctrl_entrypoint.cpp`
  - `src/login_handler.cpp`
  - `tests/test_login_real_server.cpp`
  - `tests/test_device_registration.cpp` (boost/asio headers)
- **Solution**: Add `/bigobj` compiler flag to CMakeLists.txt

### 3. Windows Environment Functions
- **Issue**: `setenv`/`unsetenv` don't exist on Windows
- **Error**: `error C3861: 'setenv': identifier not found`
- **Affected Files**: `tests/test_updates_polling_handler.cpp`
- **Solution**: Use `_putenv_s`/`_putenv` on Windows
  ```cpp
  #ifdef _WIN32
  #define setenv(name, value, overwrite) _putenv_s(name, value)
  #define unsetenv(name) _putenv_s(name, "")
  #endif
  ```

## Action Items

### High Priority
1. **Fix runtime library mismatch**
   - Option A: Change `my-triplets/x64-windows.cmake` to use dynamic linking:
     ```cmake
     set(VCPKG_CRT_LINKAGE dynamic)
     set(VCPKG_LIBRARY_LINKAGE dynamic)
     ```
   - Option B: Modify CMakeLists.txt to use `/MDd` for debug, `/MD` for release
   
2. **Add /bigobj flag**
   - Add to CMakeLists.txt:
     ```cmake
     if(MSVC)
       add_compile_options(/bigobj)
     endif()
     ```

3. **Add Windows environment function wrappers**
   - Create `include/util/platform_compat.hpp`:
     ```cpp
     #pragma once
     #ifdef _WIN32
     #include <stdlib.h>
     #define setenv(name, value, overwrite) _putenv_s(name, value)
     #define unsetenv(name) _putenv_s(name, "")
     #else
     #include <cstdlib>
     #endif
     ```

### Medium Priority
4. **Optimize encoding configuration**
   - Verify UTF-8 output is working correctly
   - Test English language output

5. **Test build with fixes**
   - Clean build directory
   - Reconfigure with corrected settings
   - Verify all targets build successfully

## Build Configuration

### Current Settings
- **Preset**: `windows-debug`
- **Build Directory**: `build/windows-debug`
- **Compiler**: MSVC 19.44 (Visual Studio 2022 Community)
- **C++ Standard**: C++20
- **Triplet**: `x64-windows` (static linkage configured)
- **Runtime**: Configured for `/MT` (static), but using `/MDd` (dynamic debug)

### Recommended Settings for Windows
```cmake
# In CMakeLists.txt
if(MSVC)
  # Use dynamic runtime for compatibility with vcpkg default
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  
  # Add /bigobj for large object files
  add_compile_options(/bigobj)
  
  # Windows-specific defines
  add_definitions(-DWIN32_LEAN_AND_MEAN -DNOMINMAX)
  
  # Link ws2_32 for networking
  link_libraries(ws2_32)
endif()
```

### vcpkg Triplet (Dynamic Linkage)
Create `my-triplets/x64-windows-dynamic.cmake`:
```cmake
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_PLATFORM_TOOLSET_VERSION 143)
set(VCPKG_CMAKE_SYSTEM_NAME Windows)
```

## Testing Status
- ✅ UTF-8 encoding working
- ✅ English language output configured
- ⚠️ Compilation incomplete due to linker errors
- ❌ Tests not yet run
- ❌ Main executable not built

## Next Steps
1. Decide on runtime linkage strategy (dynamic vs static)
2. Apply `/bigobj` flag
3. Add Windows compatibility wrappers for `setenv`/`unsetenv`
4. Clean rebuild
5. Test compilation
6. Run tests
7. Verify application functionality
