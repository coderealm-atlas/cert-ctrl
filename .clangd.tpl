# linux
CompileFlags:
  Remove: [-fsanitize=address]
  Add:
    - "-I/home/jianglibo/cert-ctrl/build/debug-asan"
    - "-isystem/home/jianglibo/cert-ctrl/build/debug-asan/vcpkg_installed/x64-linux-cpp17/include"
    - "-resource-dir=/usr/lib/llvm-14/lib/clang/14.0.0"

# macos
CompileFlags:
  Remove: [-fsanitize=address]
  Add:
    - "-I/Users/jianglibo/cert-ctrl/build/macos-debug"
    - "-isystem/Users/jianglibo/cert-ctrl/build/macos-debug/vcpkg_installed/x64-osx-cpp17/include"
    - "-resource-dir=/usr/local/opt/llvm@18/lib/clang/18"