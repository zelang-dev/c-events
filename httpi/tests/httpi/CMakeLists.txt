set(TARGETS_LIST
 test-http_auth
 test-http_connect
 test-http_download
 test-http_route
 test-http_upload
 test-http_websocket_connect
 test-httpi_http_server
 test-httpi_https_server
 test-httpi_setup
 test-httpi_units
)

foreach (TARGETS ${TARGETS_LIST})
    add_executable(${TARGETS} ${TARGETS}.c )
    target_link_libraries(${TARGETS} ${SUB_PROJECT})
    add_test(NAME ${TARGETS} COMMAND ${TARGETS} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()

add_executable(cgi_test cgi_test.c)
target_link_libraries(cgi_test ${SUB_PROJECT})