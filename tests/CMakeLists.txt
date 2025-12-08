
set(TARGET_LIST
 test-arrays
 test-changelist
 test-closed
 test-eof
 test-task_group
 test-thread
 test-time
 test-tls_static
 test-queue_work
)

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} ${PROJECT_NAME})
    add_test(NAME ${TARGET} COMMAND ${TARGET} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()

add_executable(test-getopts test-getopts.c)
target_link_libraries(test-getopts  ${PROJECT_NAME})
add_test(NAME test-getopts COMMAND test-getopts garbage -n nothing -bool
WORKING_DIRECTORY ${CMAKE_BINARY_DIR})