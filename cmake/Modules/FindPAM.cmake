find_path(PAM_INCLUDE_DIR security/pam_appl.h)
find_library(PAM_LIBRARY pam)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PAM DEFAULT_MSG PAM_INCLUDE_DIR PAM_LIBRARY)

if (PAM_FOUND)
    set(PAM_LIBRARIES ${PAM_LIBRARY})
    set(PAM_INCLUDE_DIRS ${PAM_INCLUDE_DIR})
endif()

