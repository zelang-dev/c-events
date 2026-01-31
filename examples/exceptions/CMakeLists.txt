
set(TARGET_LIST
 throw_no_try_protected
 throw_no_try
 try_catch_any
 try_catch_if_sigsegv
 try_catch_if
 try_catch_raise
 try_catch
 try_double_rethrow
 try_finally
 try_free_protected
 try_protect
 try_protected
 try_rethrow
 try_signal_sigfpe
 try_signal_sigsegv
 try_unprotected )
foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c )
    target_link_libraries(${TARGET} ${PROJECT_NAME})
endforeach()
