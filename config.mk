PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CC = c99

CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CFLAGS   =
LDFLAGS  =

G = -g

DEFAULT_SUPPORT = true
# Set to "true" to enable all algorithms that are not explicitly disabled.
# Set to "false" to disable all algorithms that are not explicitly enabled.
