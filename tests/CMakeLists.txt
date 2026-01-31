
set(TARGET_LIST
 test-arrays
 test-changelist
 test-closed
 test-eof
 test-task_group
 test-yielding
 test-thread
 test-time
 test-thrd_static
 test-dns
 test-spawn
 test-fs
 test-waitgroup
 test-fs_events
 test-parse_uri
 test-defer
 test-exceptions
)

add_executable(test-getopts test-getopts.c)
target_link_libraries(test-getopts  ${PROJECT_NAME})
add_test(NAME test-getopts COMMAND test-getopts garbage -n nothing -bool
WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(child child.c)
target_link_libraries(child ${PROJECT_NAME})

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} ${PROJECT_NAME})
	if(UNIX)
		add_test(NAME ${TARGET} COMMAND ${TARGET} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
	else()
		if (CMAKE_CONFIGURATION_TYPES MATCHES Debug)
			add_test(NAME ${TARGET} COMMAND ${TARGET} WORKING_DIRECTORY ${BUILD_DIR}/Debug)
		else()
			add_test(NAME ${TARGET} COMMAND ${TARGET} WORKING_DIRECTORY ${BUILD_DIR}/Release)
		endif()
	endif()
endforeach()
