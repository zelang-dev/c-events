#[=======================================================================[

FindHttpi
------------

Find the HttPi - dual webclient/server processor.

Imported Targets
^^^^^^^^^^^^^^^^

This module defines the following imported targets:

HTTPI::WEB
    The HttPi library, if found.

Result Variables
^^^^^^^^^^^^^^^^

This module will set the following variables in your project:

``HTTPI_FOUND``
    System has the HttPi library.
``HTTPI_INCLUDE_DIR``
    The HttPi include directory.
``HTTPI_LIBRARY``
    The HttPi library.
``HTTPI_VERSION``
    This is set to $major.$minor.$revision (e.g. 2.6.8).

Hints
^^^^^

Set HTTPI_ROOT_DIR to the root directory of an HttPi installation.

]=======================================================================]

# Find TLS Library
find_library(httpi_LIBRARY
    NAMES
        httpi
        libhttpi
)
mark_as_advanced(httpi_LIBRARY)

# Find Include Path
find_path(httpi_INCLUDE_DIR
    NAMES httpi.h
)
mark_as_advanced(httpi_INCLUDE_DIR)

include (FindPackageHandleStandardArgs)
# Set Find Package Arguments
find_package_handle_standard_args(httpi
    FOUND_VAR httpi_FOUND
    REQUIRED_VARS HTTPI_LIBRARY HTTPI_INCLUDE_DIR
    VERSION_VAR HTTPI_VERSION
    HANDLE_COMPONENTS
        FAIL_MESSAGE
        "Could NOT find HttPi, try setting the path to HttPi using the HTTPI_ROOT_DIR environment variable"
)

set(HTTPI_FOUND ${httpi_FOUND})
set(HTTPI_LIBRARY ${HTTPI_LIBRARY})

# HttPi Found
if(HTTPI_FOUND)
	set(HTTPI_INCLUDE_DIRS ${HTTPI_INCLUDE_DIR})
	set(HTTPI_LIBRARIES ${HTTPI_LIBRARY})
    if(NOT TARGET HTTPI::WEB)
        add_library(HTTPI::WEB UNKNOWN IMPORTED)
        set_target_properties(HTTPI::WEB PROPERTIES
			IMPORTED_LOCATION "${HTTPI_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${HTTPI_INCLUDE_DIRS}"
        )
    endif()
endif(HTTPI_FOUND)
