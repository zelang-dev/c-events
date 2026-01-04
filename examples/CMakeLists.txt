
set(TARGET_LIST
	argdumper
	child_command
	_cat
	_mkfifo
	bench_cascade
	event-read-fifo
	events_echo
	signal-test
	time-test
	task_group
	generator
	task_multi-args
	task_sleep
	dns_ip
	dns
	tcp_proxy
	helloworld
	spawn
 	waitgroup
)

foreach (TARGET ${TARGET_LIST})
    add_executable(${TARGET} ${TARGET}.c)
    target_link_libraries(${TARGET} ${PROJECT_NAME})
endforeach()
