AUTOMAKE_OPTIONS = subdir-objects

lib_LIBRARIES = libhash.a
libhash_a_SOURCES = src/sha.c
include_HEADERS = include/sha.h

D_MK = .build
TEST_DIR = tests

D = NDEBUG -g
LINTER_FLAGS = -Wall -Wextra -Wpedantic
OPT_FLAG = -O3
AM_CPPFLAGS = -I$(top_srcdir)/include
C_FLAGS = $(LINTER_FLAGS) $(OPT_FLAG) -D$(D) $(AM_CPPFLAGS)

# Clean up automake-generated files
clean-local:
	-rm -rf autom4te.cache config.h config.h.in~ config.log config.status compile \
		Makefile.in aclocal.m4 install-sh missing depcomp configure configure\~ ar-lib 

# Make "make distcheck" work with non-GNU tar
DISTCHECK_CONFIGURE_FLAGS = --disable-dependency-tracking

EXTRA_DIST = $(top_srcdir)/include/* $(top_srcdir)/src/*

test:
	@for test_file in $(TEST_DIR)/*.c; do \
		test_name=$$(basename $$test_file .c); \
        test_exe=$(D_MK)/$$test_name; \
        $(CC) $(C_FLAGS) -o $$test_exe $$test_file $(libhash_a_SOURCES); \
        ./$$test_exe; \
        rm -f $$test_exe; \
    done
