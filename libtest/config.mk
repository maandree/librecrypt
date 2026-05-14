WITH_BACKTRACE = true
IMPLEMENT_MMAP = true

TEST_CONFIGFILE = config_backtraces=$(WITH_BACKTRACE).mk
include $(TEST_INCLUDE_PREFIX)$(TEST_CONFIGFILE)

# If IMPLEMENT_MMAP is false, it is assumed that libc provides __mmap,
# __munmap, and __mremap as aliases for mmap, mumap, and mremap. If
# this isn't the case for your libc, but it provides other aliases,
# you can add e.g. "-D__mmap=_mmap -D__munmap=_munmap -D__mremap=_mremap"
# to specify the alises libc provides (in this example _mmap, _munmap,
# and _mremap). NB! "-D__mmap=mmap -D__munmap=munmap -D__mremap=mremap"
# is not allowed as libtest overrides mmap(3), munmap(3), and mremap(3).
