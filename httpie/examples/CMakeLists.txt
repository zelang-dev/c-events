set(TARGET_LIST
 map_insert
 slice_ref
 fetch_parse
 )
foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c )
    target_link_libraries(${TARGET} ${SUB_PROJECT})
endforeach()
