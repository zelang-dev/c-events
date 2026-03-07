#[=======================================================================[

FindHttpie
------------

Find the Httpie - dual webclient/server processor.

Imported Targets
^^^^^^^^^^^^^^^^

This module defines the following imported targets:

HTTPIE::WEB
    The httpie tls library, if found.

Result Variables
^^^^^^^^^^^^^^^^

This module will set the following variables in your project:

``HTTPIE_FOUND``
    System has the httpie library.
``HTTPIE_INCLUDE_DIR``
    The httpie include directory.
``HTTPIE_LIBRARY``
    The httpie library.
``HTTPIE_VERSION``
    This is set to $major.$minor.$revision (e.g. 2.6.8).

Hints
^^^^^

Set HTTPIE_ROOT_DIR to the root directory of an httpie installation.

]=======================================================================]

# Find TLS Library
find_library(httpie_LIBRARY
    NAMES
        httpie
        libhttpie
)
mark_as_advanced(httpie_LIBRARY)

# Find Include Path
find_path(httpie_INCLUDE_DIR
    NAMES httpie.h
)
mark_as_advanced(httpie_INCLUDE_DIR)

include (FindPackageHandleStandardArgs)
# Set Find Package Arguments
find_package_handle_standard_args(httpie
    FOUND_VAR httpie_FOUND
    REQUIRED_VARS HTTPIE_LIBRARY HTTPIE_INCLUDE_DIR
    VERSION_VAR HTTPIE_VERSION
    HANDLE_COMPONENTS
        FAIL_MESSAGE
        "Could NOT find httpie, try setting the path to httpie using the HTTPIE_ROOT_DIR environment variable"
)

set(HTTPIE_FOUND ${httpie_FOUND})
set(HTTPIE_LIBRARY ${HTTPIE_LIBRARY})

# httpie Found
if(HTTPIE_FOUND)
	set(HTTPIE_INCLUDE_DIRS ${HTTPIE_INCLUDE_DIR})
	set(HTTPIE_LIBRARIES ${HTTPIE_LIBRARY})
    if(NOT TARGET HTTPIE::WEB)
        add_library(HTTPIE::WEB UNKNOWN IMPORTED)
        set_target_properties(HTTPIE::WEB PROPERTIES
			IMPORTED_LOCATION "${HTTPIE_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${HTTPIE_INCLUDE_DIRS}"
        )
    endif()
endif(HTTPIE_FOUND)
