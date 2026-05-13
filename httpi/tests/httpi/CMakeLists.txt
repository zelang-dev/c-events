set(TARGETS_LIST
 test-http_connect
 test-http_download
 test-http_upload
 test-httpi_setup
 test-httpi_http_server
 test-httpi_https_server
 test-httpi_units
)

foreach (TARGETS ${TARGETS_LIST})
    add_executable(${TARGETS} ${TARGETS}.c )
    target_link_libraries(${TARGETS} ${SUB_PROJECT})
    add_test(NAME ${TARGETS} COMMAND ${TARGETS} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()
