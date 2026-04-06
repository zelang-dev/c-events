set(SUB_PROJECT httpie)
set(SUB_PROJECT_VERSION ${PROJECT_VERSION})
set(SUB_PROJECT_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(SUB_PROJECT_DESCRIPTION "httpie - a dual Web client/server and JavaScript processor")

file(GLOB httpie_files
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c
)

set(httpie_files ${httpie_files}
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpie_authorize.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpie_io.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpie_options.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpie_start.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/httpie_ws.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/mod/mod_response.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/mod/mod_zlib.c
	${CMAKE_CURRENT_SOURCE_DIR}/src/lib/mod/mod_quickjs.c
)

if(BUILD_SHARED_LIBS)
	add_library(${SUB_PROJECT} SHARED ${httpie_files})
else()
	add_library(${SUB_PROJECT} STATIC ${httpie_files})
endif()

add_library(HTTPIE::WEB ALIAS ${SUB_PROJECT})
target_include_directories(${SUB_PROJECT}
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_include_directories(${SUB_PROJECT}
	PRIVATE $<BUILD_INTERFACE:${EVENTS_INCLUDE_DIR} $<INSTALL_INTERFACE:${EVENTS_INCLUDE_DIR})
target_link_libraries(${SUB_PROJECT} PUBLIC ${PROJECT_NAME})

find_package(ZLIB CONFIG)
if(ZLIB_FOUND)
    message(STATUS "Cmake FindZLIB: using ZLIB includes at: ${ZLIB_INCLUDE_DIRS}")
    message(STATUS "Cmake FindZLIB: using ZLIB libraries: ${ZLIB_LIBRARIES}")
else()
    FetchContent_Declare(ZLIB
        URL https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
        URL_MD5 9855b6d802d7fe5b7bd5b196a2271655
    )
    FetchContent_MakeAvailable(ZLIB)
    option(ZLIB_BUILD_EXAMPLES "Enable Zlib Examples as tests" OFF)
    option(ZLIB_BUILD_MINIZIP "Enable building libminizip contrib" OFF)
    option(ZLIB_INSTALL "Enable installation of zlib" ON)
    set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "Build tests" FORCE)
    set(ZLIB_BUILD_MINIZIP OFF CACHE BOOL "Build libminizip" FORCE)
    set(ZLIB_INSTALL ON CACHE BOOL "Install zlib" FORCE)

	file(COPY ${BUILD_DIR}/_deps/zlib-src/zlib.h DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/src/lib)
	file(COPY ${BUILD_DIR}/_deps/zlib-build/zconf.h DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/src/lib)
endif()
target_include_directories(${SUB_PROJECT}
	PRIVATE $<BUILD_INTERFACE:${ZLIB_INCLUDE_DIRS} $<INSTALL_INTERFACE:${ZLIB_INCLUDE_DIRS})
target_link_libraries(${SUB_PROJECT} PUBLIC ${ZLIB_LIBRARIES})

find_package(quickjs QUIET)
if(NOT quickjs_FOUND)
    FetchContent_Declare(quickjs
        URL https://github.com/quickjs-ng/quickjs/archive/refs/tags/v0.13.0.zip
        URL_MD5 f78a59d68dfb75f90b4320c1901237f2
    )
    option(QJS_BUILD_LIBC "Enable building standard library" ON)
    set(QJS_BUILD_LIBC ON CACHE BOOL "BUILD standard library" FORCE)
    option(QJS_BUILD_EXAMPLES "Enable Test building" OFF)
    set(QJS_BUILD_EXAMPLES OFF CACHE BOOL "BUILD Tests" FORCE)
    FetchContent_MakeAvailable(quickjs)
endif()
target_include_directories(${SUB_PROJECT}
	PRIVATE $<BUILD_INTERFACE:${quickjs_INCLUDE_DIRS} $<INSTALL_INTERFACE:${quickjs_INCLUDE_DIRS})
target_link_libraries(${SUB_PROJECT} PUBLIC qjs)

set_target_properties(${SUB_PROJECT} PROPERTIES
	OUTPUT_NAME ${SUB_PROJECT}
	ARCHIVE_OUTPUT_NAME ${SUB_PROJECT}
	EXPORT_NAME ${SUB_PROJECT}
	VERSION  ${SUB_PROJECT_VERSION}
	SOVERSION ${SUB_PROJECT_VERSION_MAJOR}
)

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
set(CPACK_PACKAGE_VERSION ${SUB_PROJECT_VERSION})

set(CMAKE_INSTALL_CONFIG_NAME ${CMAKE_BUILD_TYPE})
set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/"${SUB_PROJECT}"
    CACHE PATH "Location of header files" )

set(SYSCONFIG_INSTALL_DIR ${CMAKE_INSTALL_SYSCONFDIR}/"${SUB_PROJECT}"
    CACHE PATH "Location of configuration files" )

configure_package_config_file(httpieConfig.cmake.in
  	${CMAKE_CURRENT_BINARY_DIR}/httpieConfig.cmake
	INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/"${SUB_PROJECT}"
	PATH_VARS INCLUDE_INSTALL_DIR SYSCONFIG_INSTALL_DIR)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/httpieConfigVersion.cmake
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
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "httpie")
set(CPACK_COMPONENT_LIBRARIES_DESCRIPTION ${SUB_PROJECT_DESCRIPTION})

set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.md)
set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_SOURCE_DIR}/README.md)

set(CPACK_PACKAGE_VENDOR "https://github.com/zelang-dev")
set(CPACK_PACKAGE_VERSION ${SUB_PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION ${SUB_PROJECT_DESCRIPTION})

set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_URL "https://zelang-dev.github.io/c-events/")
set(CPACK_RPM_PACKAGE_ARCHITECTURE "${PROJECT__ARCH}")
set(CPACK_RPM_PACKAGE_REQUIRES "zlib, zlib-devel")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/httpieConfig.cmake
	${CMAKE_CURRENT_BINARY_DIR}/httpieConfigVersion.cmake
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${SUB_PROJECT}" )

install(
	TARGETS ${SUB_PROJECT}
	EXPORT "${SUB_PROJECT}Targets"
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
	INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
	EXPORT "${SUB_PROJECT}Targets"
	FILE "${SUB_PROJECT}Targets.cmake"
	NAMESPACE HTTPIE::
	DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${SUB_PROJECT}"
)

install(TARGETS ${SUB_PROJECT} DESTINATION lib)
install(FILES include/*.h DESTINATION include)
set(CPACK_INSTALL_CMAKE_CONFIGURATIONS Release)

if(BUILD_EXAMPLES)
	add_subdirectory(examples)
endif()

if(BUILD_TESTS)
	add_subdirectory(tests)
endif()
