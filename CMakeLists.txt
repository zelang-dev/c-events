cmake_minimum_required (VERSION 3.14...4.1.0)
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
	cmake_policy(SET CMP0091 NEW)
endif()

project(events
	VERSION 0.6.0
	DESCRIPTION "A tiny, lightning fast, event loop, using either `epoll`, `kqueue`, or `wepoll` and `iocp` for Windows."
    LANGUAGES C
)

set(CMAKE_C_STANDARD 90)

include(FetchContent)
include(CheckLibraryExists)
include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(GNUInstallDirs)
include(CTest)

set(BUILD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/built")
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" ${CMAKE_MODULE_PATH}/cmake)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

option(BUILD_SHARED_LIBS "Build the library as a shared (dynamically-linked) " OFF)

message("Generated with config types: ${CMAKE_CONFIGURATION_TYPES}")
set(CMAKE_CONFIGURATION_TYPES=Debug;Release)

set(ev_sources
	${CMAKE_CURRENT_SOURCE_DIR}/src/rpmalloc.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/events.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/except.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/arrays.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/os_async.c)
if(WIN32)
	set(ev_sources ${ev_sources}
	${CMAKE_CURRENT_SOURCE_DIR}/src/os_windows.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/epoll.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/wepoll.c)
	link_libraries(ws2_32)
else()
	set(ev_sources ${ev_sources}
	${CMAKE_CURRENT_SOURCE_DIR}/src/os_unix.c)
	if(APPLE OR CMAKE_SYSTEM_NAME MATCHES "DragonFly|FreeBSD|NetBSD|OpenBSD")
  		set(ev_sources ${ev_sources} ${CMAKE_CURRENT_SOURCE_DIR}/src/kqueue.c)
  	else()
  		set(ev_sources ${ev_sources} ${CMAKE_CURRENT_SOURCE_DIR}/src/epoll.c)
  	endif()
endif()

if(UNIX)
    if(APPLE)
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wno-format -fno-pie -D USE_DEBUG -D ENABLE_ASSERTS ")
    else()
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -rdynamic -no-pie -Wno-format -D USE_DEBUG -D ENABLE_ASSERTS ")
    endif()
else()
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /D USE_DEBUG /D ENABLE_ASSERTS ")
    if($ENV{Platform} MATCHES x86)
        message("Building Windows x86-32bit")
        add_definitions(-D_WIN32_PLATFORM_X86=1)
    endif()
endif()

if(BUILD_SHARED_LIBS)
	add_library(${PROJECT_NAME} SHARED ${ev_sources})
else()
	add_library(${PROJECT_NAME} STATIC ${ev_sources})
endif()
add_library(EVENTS::LOOP ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME}
 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_include_directories(${PROJECT_NAME}
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

if(UNIX)
	find_package(Threads)
    if(APPLE)
        target_link_libraries(${PROJECT_NAME} PUBLIC ${CMAKE_THREAD_LIBS_INIT})
    else()
        target_link_libraries(${PROJECT_NAME} PUBLIC ${CMAKE_THREAD_LIBS_INIT} atomic)
    endif()
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES
	OUTPUT_NAME ${PROJECT_NAME}
	ARCHIVE_OUTPUT_NAME ${PROJECT_NAME}
	EXPORT_NAME ${PROJECT_NAME}
	VERSION  ${PROJECT_VERSION}
	SOVERSION ${PROJECT_VERSION_MAJOR}
)

if(NOT CMAKE_VERSION VERSION_LESS 3.27.0)
	set_target_properties(${PROJECT_NAME} PROPERTIES DLL_NAME_WITH_SOVERSION TRUE)
endif()

set(_fmt TGZ)
if(WIN32)
  set(_fmt ZIP)
endif()

set(CPACK_GENERATOR ${_fmt})
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_NUGET_COMPONENT_INSTALL ON)
set(CPACK_WIX_COMPONENT_INSTALL ON)
set(CPACK_NSIS_MODIFY_PATH ON)
set(CPACK_COMPONENTS_ALL_IN_ONE_PACKAGE 1)
set(CPACK_VERBATIM_VARIABLES YES)

set(CPACK_PACKAGE_VENDOR "https://github.com/zelang-dev/c-events")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})

set(CMAKE_INSTALL_CONFIG_NAME ${CMAKE_BUILD_TYPE})
set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
    CACHE PATH "Location of header files" )

set(SYSCONFIG_INSTALL_DIR ${CMAKE_INSTALL_SYSCONFDIR}/${PROJECT_NAME}
    CACHE PATH "Location of configuration files" )

configure_package_config_file(eventsConfig.cmake.in
  	${CMAKE_CURRENT_BINARY_DIR}/eventsConfig.cmake
	INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
	PATH_VARS INCLUDE_INSTALL_DIR SYSCONFIG_INSTALL_DIR)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/eventsConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion )

set(CPACK_PACKAGE_DIRECTORY "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/Package")
set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME})
set(CPACK_PACKAGE_INSTALL_DIRECTORY ${PROJECT_NAME})

set(CPACK_PACKAGE_CONTACT "lstubbs@zelang.dev")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Lawrence Stubbs <${CPACK_PACKAGE_CONTACT}>")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "Events event loop")
set(CPACK_COMPONENT_LIBRARIES_DESCRIPTION ${PROJECT_DESCRIPTION})

set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.md)
set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_SOURCE_DIR}/README.md)

set(CPACK_PACKAGE_VENDOR "https://github.com/zelang-dev")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION})

set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_URL "https://zelang-dev.github.io/c-events/")
set(CPACK_RPM_PACKAGE_ARCHITECTURE "noarch")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/eventsConfig.cmake
	${CMAKE_CURRENT_BINARY_DIR}/eventsConfigVersion.cmake
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}" )

install(
	TARGETS ${PROJECT_NAME}
	EXPORT "${PROJECT_NAME}Targets"
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
	EXPORT "${PROJECT_NAME}Targets"
	FILE "${PROJECT_NAME}Targets.cmake"
	NAMESPACE EVENTS::
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
)

install(TARGETS ${PROJECT_NAME} DESTINATION lib)
if(WIN32)
    install(DIRECTORY include/ DESTINATION include )
else()
	install(FILES include/*.h DESTINATION include)
endif()
include(CPack)

if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    option(BUILD_EXAMPLES "whether or not examples should be built" ON)
    option(BUILD_TESTS "whether or not tests should be built" ON)

    if(BUILD_EXAMPLES)
        add_subdirectory(examples)
        add_subdirectory(examples/exceptions)
    endif()

    if(BUILD_TESTS)
        enable_testing()
        add_subdirectory(tests)
    endif()
endif()