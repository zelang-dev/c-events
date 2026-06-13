cmake_minimum_required (VERSION 3.14...5.1.0)

if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
	cmake_policy(SET CMP0091 NEW)
endif()

project(httpi
	VERSION 0.1.0
	DESCRIPTION "Httpi - a dual Web client/server and JavaScript processor"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 90)

include(FetchContent)
include(CheckLibraryExists)
include(CMakePackageConfigHelpers)
include(CMakeDependentOption)
include(GNUInstallDirs)
include(CTest)

set(SUB_PROJECT ${PROJECT_NAME})
set(SUB_PROJECT_APP url)
set(SUB_PROJECT_VERSION ${PROJECT_VERSION})
set(SUB_PROJECT_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(SUB_PROJECT_DESCRIPTION ${PROJECT_DESCRIPTION})

set(BUILD_DIR ${CMAKE_SOURCE_DIR}/build)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/built")
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

option(BUILD_SHARED_LIBS "Build the library as a shared (dynamically-linked) " OFF)
option(BUILD_HTTPI_APP "`url` frontend app for `httpi`" OFF)

message("Generated with config types: ${CMAKE_CONFIGURATION_TYPES}")
set(CMAKE_CONFIGURATION_TYPES=Debug;Release)

if(UNIX)
    if(APPLE)
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D USE_DEBUG")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wabi -D _DARWIN_UNLIMITED_SELECT=1 -D _DARWIN_USE_64_BIT_INODE=1")
    else()
		set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -rdynamic -no-pie -D USE_DEBUG")
    endif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-format -fno-strict-aliasing -Wstrict-prototypes -DZLIB_INSECURE=1")
else()
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /D USE_DEBUG")
endif()

file(GLOB httpi_files
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c
)

set(httpi_files ${httpi_files}
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpi_authorize.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpi_io.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpi_options.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpi_request.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpi_start.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpi_ws.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/mod/mod_http2.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/mod/mod_quickjs.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/mod/mod_response.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/mod/mod_zlib.c
)

if(BUILD_SHARED_LIBS)
	add_library(${SUB_PROJECT} SHARED ${httpi_files})
else()
	add_library(${SUB_PROJECT} STATIC ${httpi_files})
    add_definitions(-DZLIB_STATIC=1)
endif()

add_library(HTTPI::WEB ALIAS ${SUB_PROJECT})
target_include_directories(${SUB_PROJECT}
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_include_directories(${SUB_PROJECT}
	PRIVATE $<BUILD_INTERFACE:${EVENTS_INCLUDE_DIR} $<INSTALL_INTERFACE:${EVENTS_INCLUDE_DIR})
target_link_libraries(${SUB_PROJECT} PUBLIC EVENTS::LOOP)

find_package(ZLIB CONFIG)
if(ZLIB_FOUND)
    message(STATUS "Cmake FindZLIB: using ZLIB includes at: ${ZLIB_INCLUDE_DIRS}")
    message(STATUS "Cmake FindZLIB: using ZLIB libraries: ${ZLIB_LIBRARIES}")
else()
    FetchContent_Declare(ZLIB
        URL https://github.com/madler/zlib/archive/refs/tags/v1.3.2.zip
        URL_MD5 adbba6eef8960c3412818b2e241f46dc
    )
    option(ZLIB_BUILD_TESTING "Enable Zlib Examples as tests" OFF)
    option(ZLIB_BUILD_MINIZIP "Enable minizip" OFF)
    option(ZLIB_INSTALL "Enable installation of zlib" ON)
	if(NOT BUILD_SHARED_LIBS)
    	option(ZLIB_BUILD_STATIC "Enable static build of zlib" ON)
	endif()
    FetchContent_MakeAvailable(ZLIB)
    set(ZLIB_BUILD_TESTING OFF CACHE BOOL "Build tests" FORCE)
    set(ZLIB_BUILD_MINIZIP OFF CACHE BOOL "Build minizip" FORCE)
    set(ZLIB_INSTALL ON CACHE BOOL "Install zlib" FORCE)
	if(NOT BUILD_SHARED_LIBS)
    	set(ZLIB_BUILD_STATIC ON CACHE BOOL "Insbuild static zlib" FORCE)
	endif()
endif()
target_include_directories(${SUB_PROJECT}
	PRIVATE $<BUILD_INTERFACE:${ZLIB_INCLUDE_DIRS} $<INSTALL_INTERFACE:${ZLIB_INCLUDE_DIRS})

if(BUILD_SHARED_LIBS)
	target_link_libraries(${SUB_PROJECT} PUBLIC ZLIB::ZLIB)
else()
	set(ENV{QJS_BUILD_CLI_STATIC} "ON")
	target_link_libraries(${SUB_PROJECT} PUBLIC ZLIB::ZLIBSTATIC)
endif()

find_package(quickjs QUIET)
if(NOT quickjs_FOUND)
	set(ENV{QJS_BUILD_EXAMPLES} "OFF")
    if(WIN32)
		set(ENV{QJS_BUILD_CLI_STATIC} "ON")
	else()
		set(ENV{QJS_BUILD_CLI_STATIC} "OFF")
    endif()
	set(ENV{QJS_BUILD_LIBC} "ON")
    FetchContent_Declare(quickjs
        URL https://github.com/quickjs-ng/quickjs/archive/refs/tags/v0.15.0.zip
        URL_MD5 aa1dd87703c7199a6267352107b842ee
    )
    FetchContent_MakeAvailable(quickjs)
endif()
target_include_directories(${SUB_PROJECT}
	PRIVATE $<BUILD_INTERFACE:${quickjs_INCLUDE_DIRS} $<INSTALL_INTERFACE:${quickjs_INCLUDE_DIRS})
	if(WIN32)
		target_include_directories(qjs PRIVATE ${CMAKE_SOURCE_DIR}/include)
		target_include_directories(run-test262 PRIVATE ${CMAKE_SOURCE_DIR}/include)
	endif()
target_link_libraries(${SUB_PROJECT} PUBLIC qjs)

# The executable
if (BUILD_HTTPI_APP)
    if(APPLE)
		file(GLOB URL_RES ${CMAKE_CURRENT_SOURCE_DIR}resources/url*.*)
		set_source_files_properties(${URL_RES} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
    	add_executable(${SUB_PROJECT_APP} MACOSX_BUNDLE ${CMAKE_CURRENT_SOURCE_DIR}/src/app/url.c ${URL_RES})
		find_library(COCOA_LIBRARY Cocoa required)
		target_link_libraries(${SUB_PROJECT_APP} ${SUB_PROJECT} ${COCOA_LIBRARY})
		set(CPACK_BUNDLE_NAME "Url")
		set(CPACK_BUNDLE_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/resources/info.plist)
		set(CPACK_BUNDLE_ICON ${CMAKE_CURRENT_SOURCE_DIR}/resources/url_64x64.png)
	else()
		if(WIN32)
        	add_executable(${SUB_PROJECT_APP} ${CMAKE_CURRENT_SOURCE_DIR}/src/app/url.c
				${CMAKE_CURRENT_SOURCE_DIR}/resources/res.rc)
		else()
    		add_executable(${SUB_PROJECT_APP} ${CMAKE_CURRENT_SOURCE_DIR}/src/app/url.c)
		endif()
    	target_link_libraries(${SUB_PROJECT_APP} ${SUB_PROJECT})
    endif()

    target_include_directories(
        ${SUB_PROJECT_APP} PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

    set_target_properties(${SUB_PROJECT_APP} PROPERTIES
        EXPORT_NAME ${SUB_PROJECT_APP}
        OUTPUT_NAME ${SUB_PROJECT_APP}
		VERSION ${SUB_PROJECT_VERSION}
		SOVERSION ${SUB_PROJECT_VERSION_MAJOR}
    )

	install(
		TARGETS ${SUB_PROJECT_APP}
        COMPONENT Runtime
        DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()

set_target_properties(${SUB_PROJECT} PROPERTIES
	OUTPUT_NAME ${SUB_PROJECT}
	ARCHIVE_OUTPUT_NAME ${SUB_PROJECT}
	EXPORT_NAME ${SUB_PROJECT}
	VERSION  ${SUB_PROJECT_VERSION}
	SOVERSION ${SUB_PROJECT_VERSION_MAJOR}
)

if(NOT CMAKE_VERSION VERSION_LESS 3.27.0)
	set_target_properties(${SUB_PROJECT} PROPERTIES DLL_NAME_WITH_SOVERSION TRUE)
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

set(CPACK_PACKAGE_VENDOR "https://github.com/zelang-dev/httpi")
set(CPACK_PACKAGE_VERSION ${SUB_PROJECT_VERSION})

set(CMAKE_INSTALL_CONFIG_NAME ${CMAKE_BUILD_TYPE})
set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/"${SUB_PROJECT}"
    CACHE PATH "Location of header files" )

set(SYSCONFIG_INSTALL_DIR ${CMAKE_INSTALL_SYSCONFDIR}/"${SUB_PROJECT}"
    CACHE PATH "Location of configuration files" )

configure_package_config_file(httpiConfig.cmake.in
  	${CMAKE_CURRENT_BINARY_DIR}/httpiConfig.cmake
	INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/"${SUB_PROJECT}"
	PATH_VARS INCLUDE_INSTALL_DIR SYSCONFIG_INSTALL_DIR)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/httpiConfigVersion.cmake
  VERSION ${SUB_PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion )

set(CPACK_PACKAGE_DIRECTORY "${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/Package")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${SUB_PROJECT}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY ${SUB_PROJECT})
set(CPACK_PACKAGE_DEPENDS "zlib")

set(CPACK_PACKAGE_CONTACT "lstubbs@zelang.dev")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Lawrence Stubbs <${CPACK_PACKAGE_CONTACT}>")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "${PROJECT__ARCH}")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "zlib1g, zlib1g-dev")

set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "HttPi")
set(CPACK_COMPONENT_LIBRARIES_DESCRIPTION ${SUB_PROJECT_DESCRIPTION})

set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.md)
set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_SOURCE_DIR}/README.md)

set(CPACK_PACKAGE_VENDOR "https://github.com/zelang-dev")
set(CPACK_PACKAGE_VERSION ${SUB_PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION ${SUB_PROJECT_DESCRIPTION})

set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_URL "https://zelang-dev.github.io/httpi/")
set(CPACK_RPM_PACKAGE_ARCHITECTURE "${PROJECT__ARCH}")
set(CPACK_RPM_PACKAGE_REQUIRES "zlib, zlib-devel")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/httpiConfig.cmake
	${CMAKE_CURRENT_BINARY_DIR}/httpiConfigVersion.cmake
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${SUB_PROJECT}" )

if (BUILD_HTTPI_APP)
	set(HTTPI ${SUB_PROJECT} ${SUB_PROJECT_APP} ${ZLIB} ${qjs})
else()
	set(HTTPI ${SUB_PROJECT} ${ZLIB} ${qjs})
endif()

if(APPLE)
	install(
		TARGETS ${HTTPI}
		EXPORT "${SUB_PROJECT}Targets"
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		RUNTIME DESTINATION BUNDLE DESTINATION ${CMAKE_INSTALL_BINDIR}
		PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
		INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	)
else()
	install(
		TARGETS ${HTTPI}
		EXPORT "${SUB_PROJECT}Targets"
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
		PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
		INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	)
endif()

install(
	EXPORT "${SUB_PROJECT}Targets"
	FILE "${SUB_PROJECT}Targets.cmake"
	NAMESPACE HTTPI::
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${SUB_PROJECT}"
)

install(TARGETS ${SUB_PROJECT} DESTINATION lib)
if (BUILD_HTTPI_APP)
	install(TARGETS ${SUB_PROJECT_APP} DESTINATION bin)
endif()
install(FILES include/*.h DESTINATION include)
set(CPACK_INSTALL_CMAKE_CONFIGURATIONS Release)

#if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
#    option(BUILD_EXAMPLES "whether or not examples should be built" ON)
#    option(BUILD_TESTS "whether or not tests should be built" ON)

	if(BUILD_EXAMPLES)
		add_subdirectory(examples)
	endif()

	if(BUILD_TESTS)
        enable_testing()
		add_subdirectory(tests)
	endif()
#endif()
