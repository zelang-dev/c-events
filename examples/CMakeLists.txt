
set(TARGET_LIST
	_mkfifo
	argdumper
	bench_cascade
	event-read-fifo
	events_echo
	signal-test
	time-test
)

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} ${PROJECT_NAME})
endforeach()
