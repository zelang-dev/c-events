#[=======================================================================[

FindEvents
------------

Find the Events event loop library.

Imported Targets
^^^^^^^^^^^^^^^^

This module defines the following imported targets:

EVENTS::LOOP
    The events tls library, if found.

Result Variables
^^^^^^^^^^^^^^^^

This module will set the following variables in your project:

``EVENTS_FOUND``
    System has the events library.
``EVENTS_INCLUDE_DIR``
    The events include directory.
``EVENTS_LIBRARY``
    The events library.
``EVENTS_VERSION``
    This is set to $major.$minor.$revision (e.g. 2.6.8).

Hints
^^^^^

Set EVENTS_ROOT_DIR to the root directory of an events installation.

]=======================================================================]

# Find TLS Library
find_library(events_LIBRARY
    NAMES
        events
        libevents
)
mark_as_advanced(events_LIBRARY)

# Find Include Path
find_path(events_INCLUDE_DIR
    NAMES events.h
)
mark_as_advanced(events_INCLUDE_DIR)

include (FindPackageHandleStandardArgs)
# Set Find Package Arguments
find_package_handle_standard_args(events
    FOUND_VAR events_FOUND
    REQUIRED_VARS EVENTS_LIBRARY EVENTS_INCLUDE_DIR
    VERSION_VAR EVENTS_VERSION
    HANDLE_COMPONENTS
        FAIL_MESSAGE
        "Could NOT find events, try setting the path to events using the EVENTS_ROOT_DIR environment variable"
)

set(EVENTS_FOUND ${events_FOUND})
set(EVENTS_LIBRARY ${EVENTS_LIBRARY})

# events Found
if(EVENTS_FOUND)
	set(EVENTS_INCLUDE_DIRS ${EVENTS_INCLUDE_DIR})
	set(EVENTS_LIBRARIES ${EVENTS_LIBRARY})
    if(NOT TARGET EVENTS::LOOP)
        add_library(EVENTS::LOOP UNKNOWN IMPORTED)
        set_target_properties(EVENTS::LOOP PROPERTIES
			IMPORTED_LOCATION "${EVENTS_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${EVENTS_INCLUDE_DIRS}"
        )
    endif()
endif(EVENTS_FOUND)
