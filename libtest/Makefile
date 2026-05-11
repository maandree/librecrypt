.POSIX:

TEST_CONFIGFILE = config.mk
include $(TEST_CONFIGFILE)

OS = linux
# Linux:   linux
# Mac OS:  macos
# Windows: windows
include ../mk/$(OS).mk


OBJ =\
	$(OBJ_MMAP)\
	alloc.o\
	alloc_have_custom.o\
	globals.o\
	libtest_alloc.o\
	libtest_base_pointer.o\
	libtest_check_no_leaks.o\
	libtest_expect_zeroed_on_free.o\
	libtest_force_zero_on_alloc.o\
	libtest_free.o\
	libtest_get_pagesize.o\
	libtest_start_tracking.o\
	libtest_stop_tracking.o\
	libtest_dump_stack.o\
	libtest_stack_on_signal.o\
	libtest_get_alloc_failure_in.o\
	libtest_set_alloc_failure_in.o\
	random.o\
	$(OBJ_BACKTRACE)\

HDR =\
	libtest.h\
	common.h\

LOBJ = $(OBJ:.o=.lo)
TOBJ = $(OBJ:.o=.to)
TEST = $(OBJ:.o=.t)


all: libtest.a $(TEST)
$(OBJ): $(HDR)
$(LOBJ): $(HDR)
$(TOBJ): $(HDR)
$(TEST): $(HDR) libtest.a

.c.o:
	$(C17) -fno-builtin -c -o $@ $< $(TEST_CFLAGS) $(TEST_CPPFLAGS)

.c.lo:
	$(C17) -fno-builtin -fPIC -c -o $@ $< $(TEST_CFLAGS) $(TEST_CPPFLAGS)

.c.to:
	$(C17) -DTEST -c -o $@ $< $(TEST_CFLAGS) $(TEST_CPPFLAGS)

.to.t:
	$(C17) -o $@ $< libtest.a $(TEST_LDFLAGS)

.c.t:
	$(C17) -DTEST -o $@ $< libtest.a $(TEST_CFLAGS) $(TEST_CPPFLAGS) $(TEST_LDFLAGS)

libtest.a: $(OBJ)
	@rm -f -- $@
	$(AR) rc $@ $(OBJ)
	$(AR) ts $@ > /dev/null

check: $(TEST)
	@set -ex;\
	for t in $(TEST); do\
		./$$t;\
	done

clean:
	-rm -f -- *.o *.a *.lo *.su *.so *.so.* *.dll *.dylib
	-rm -f -- *.gch *.gcov *.gcno *.gcda *.$(LIBEXT)
	-rm -f -- *.to *.t

.SUFFIXES:
.SUFFIXES: .lo .o .c .to .t

.PHONY: all check install uninstall clean
