C17 !=\
	if command -v c17 >/dev/null || ! command -v cc >/dev/null; then\
		echo c17;\
	else\
		echo cc -std=c17;\
	fi

TEST_CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -DWITH_BACKTRACE
TEST_CFLAGS   = -g
TEST_LDFLAGS  = -lunwind -ldw

OBJ_BACKTRACE = libtest_print_backtrace.o
