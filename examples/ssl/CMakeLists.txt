
set(TARGET_LIST
 #tls-echo-server
 #fetch
 create-x509
)

file(COPY ../../cert.pem DESTINATION ${CMAKE_BINARY_DIR})

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} ${PROJECT_NAME})
endforeach()
