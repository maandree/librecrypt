.POSIX:

include argon2/prefix.mk


CONFIGFILE = config.mk
include $(CONFIGFILE)

OS = linux
# Linux:   linux
# Mac OS:  macos
# Windows: windows
include mk/$(OS).mk


LIB_MAJOR = 1
LIB_MINOR = 0
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)
LIB_NAME = recrypt


OBJ_PUBLIC =\
	librecrypt_settings_prefix.o\
	librecrypt_chain_length.o\
	librecrypt_decompose_chain.o\
	librecrypt_decompose_chain1.o\
	librecrypt_next_algorithm.o\
	librecrypt_encode.o\
	librecrypt_decode.o\
	librecrypt_get_encoding.o\
	librecrypt_wipe.o\
	librecrypt_wipe_str.o\
	librecrypt_equal_binary.o\
	librecrypt_equal.o\
	librecrypt_realise_salts.o\
	librecrypt_make_settings.o\
	librecrypt_hash_binary.o\
	librecrypt_hash.o\
	librecrypt_crypt.o\
	librecrypt_add_algorithm.o\
	librecrypt_test_supported.o\

OBJ_PRIVATE =\
	librecrypt_algorithms_.o\
	librecrypt_hash_.o\
	librecrypt_rng_.o\
	librecrypt_fill_with_random_.o\
	librecrypt_find_first_algorithm_.o\
	librecrypt_check_settings_.o\
	$(OBJ_COMMON_RFC4848S4)

USE_OBJ_COMMON_RFC4848S4 =\
	librecrypt_common_rfc4848s4_encoding_lut_.o\
	librecrypt_common_rfc4848s4_decoding_lut_.o

OBJ = $(OBJ_PUBLIC) $(OBJ_PRIVATE)

HDR =\
	librecrypt.h\
	common.h\
	algorithms.h

LOBJ = $(OBJ:.o=.lo)
TOBJ = $(OBJ:.o=.to)
TEST = $(OBJ:.o=.t)
MAN3 = $(OBJ_PUBLIC:.o=.3)
MAN7 = librecrypt.7

all:

include argon2/suffix.mk

ALL_CFLAGS   = $(CFLAGS)   $(CFLAGS_MODULES)
ALL_CPPFLAGS = $(CPPFLAGS) $(CPPFLAGS_MODULES)
ALL_LDFLAGS  = $(LDFLAGS)  $(LDFLAGS_MODULES)

TEST_INCLUDE_PREFIX = libtest/
include libtest/config.mk


all: librecrypt.a librecrypt.$(LIBEXT) $(TEST)
$(OBJ): $(HDR)
$(LOBJ): $(HDR)
$(TOBJ): $(HDR) libtest/libtest.h
$(TEST): $(HDR) librecrypt.a libtest/libtest.a libtest/libtest.h

.c.o:
	$(CC) -c -o $@ $< $(ALL_CFLAGS) $(COV_CFLAGS) $(ALL_CPPFLAGS) $(COV_CPPFLAGS)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(ALL_CFLAGS) $(COV_CFLAGS) $(ALL_CPPFLAGS) $(COV_CPPFLAGS)

.c.to:
	$(CC) -DTEST -c -o $@ $< $(ALL_CFLAGS) $(ALL_CPPFLAGS)

.to.t:
	$(CC) -o $@ $< librecrypt.a libtest/libtest.a $(G) $(ALL_LDFLAGS) $(TEST_LDFLAGS) $(COV_LDFLAGS)

librecrypt.a: $(OBJ)
	@rm -f -- $@
	$(AR) rc $@ $(OBJ)
	$(AR) ts $@ > /dev/null

librecrypt.$(LIBEXT): $(LOBJ)
	$(CC) $(LIBFLAGS) -o $@ $(LOBJ) $(LDFLAGS)

libtest/libtest.a:
	+cd libtest && $(MAKE) libtest.a

check: $(TEST)
	+cd libtest && $(LIBTEST_CHECK_PREFIX) $(MAKE) check
	@set -ex;\
	for t in $(TEST); do\
		$(CHECK_PREFIX) ./$$t;\
	done
# Setting CHECK_PREFIX is intended for developers, setting it
# (specially to use valgrind(1)) may limit what the test code
# is able to test

install: librecrypt.a librecrypt.$(LIBEXT)
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man3"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man7"
	cp -- librecrypt.a "$(DESTDIR)$(PREFIX)/lib/"
	cp -- librecrypt.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/librecrypt.$(LIBMINOREXT)"
	$(FIX_INSTALL_NAME) "$(DESTDIR)$(PREFIX)/lib/librecrypt.$(LIBMINOREXT)"
	ln -sf -- librecrypt.$(LIBMINOREXT) "$(DESTDIR)$(PREFIX)/lib/librecrypt.$(LIBMAJOREXT)"
	ln -sf -- librecrypt.$(LIBMAJOREXT) "$(DESTDIR)$(PREFIX)/lib/librecrypt.$(LIBEXT)"
	cp -- librecrypt.h "$(DESTDIR)$(PREFIX)/include/"
	cp -P -- $(MAN3) "$(DESTDIR)$(MANPREFIX)/man3/"
	cp -P -- $(MAN7) "$(DESTDIR)$(MANPREFIX)/man7/"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/librecrypt.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/librecrypt.$(LIBMAJOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/librecrypt.$(LIBMINOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/librecrypt.$(LIBEXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/include/librecrypt.h"
	-cd -- "$(DESTDIR)$(MANPREFIX)/man3/" && rm -f -- $(MAN3)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man7/" && rm -f -- $(MAN7)

clean:
	-rm -f -- *.o *.a *.lo *.su *.so *.so.* *.dll *.dylib
	-rm -f -- *.gch *.gcov *.gcno *.gcda *.$(LIBEXT)
	-rm -f -- *.to *.t

.SUFFIXES:
.SUFFIXES: .lo .o .c .to .t

.PHONY: all check install uninstall clean
