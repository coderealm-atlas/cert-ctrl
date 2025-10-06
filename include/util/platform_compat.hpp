#pragma once

// Platform compatibility layer for POSIX/Windows functions

#ifdef _WIN32
    #include <stdlib.h>
    // Windows doesn't have setenv/unsetenv, use _putenv_s instead
    #define setenv(name, value, overwrite) _putenv_s(name, value)
    #define unsetenv(name) _putenv_s(name, "")
#else
    // POSIX systems have standard setenv/unsetenv
    #include <cstdlib>
#endif
