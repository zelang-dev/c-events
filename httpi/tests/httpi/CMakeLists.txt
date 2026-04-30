set(TARGETS_LIST
 unit_test
)

foreach (TARGETS ${TARGETS_LIST})
    add_executable(${TARGETS} ${TARGETS}.c )
    target_link_libraries(${TARGETS} ${SUB_PROJECT})
    add_test(NAME ${TARGETS} COMMAND ${TARGETS} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()
