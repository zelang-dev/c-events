
set(TARGET_LIST
 test-arrays
 test-changelist
 test-closed
 test-eof
 test-task_group
 test-thread
 test-time
)

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} ${PROJECT_NAME})
    add_test(NAME ${TARGET} COMMAND ${TARGET} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()
