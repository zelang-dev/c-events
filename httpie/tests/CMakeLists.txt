set(TARGET_LIST
 test-hashmap
 test-http_request
 test-http_response
 test-parse_multibad
 test-parse_multipart
 test-parse_http
 test-json
 test-json_parser
 test-slice
)

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c )
    target_link_libraries(${TARGET} ${SUB_PROJECT})
    add_test(NAME ${TARGET} COMMAND ${TARGET} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()
