CONFIGFILE_PROPER = config.mk
include $(CONFIGFILE_PROPER)

CC = $(CC_PREFIX)clang -std=c99

SANITIZE        = $(CLANG_SANITIZE)
FUZZ_CFLAGS     = -fsanitize=fuzzer
FUZZ_LDFLAGS    = -fsanitize=fuzzer
FUZZED_CPPFLAGS = -DFUZZ

all: fuzz

# These configurations will modify the library code
# so that it doesn't perform password hashing !!!!!
