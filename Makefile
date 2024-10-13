INC := $(wildcard include/*.h)
SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)
TST := $(wildcard tests/*.c)
TSX := $(TST:.c=.out)

ARFLAGS := rcs

CFLAGS ?= -O3 -Wextra -Wshadow -pedantic -fPIC
override CFLAGS += -Iinclude/

ifeq ($(DEBUG), 1)
	override CFLAGS += -g
endif


PREFIX ?= /usr/local
INCLUDEDIR := $(PREFIX)/include/libhash
LIBDIR := $(PREFIX)/lib

all: libhash.a


libhash.a: $(OBJ)
	$(AR) $(ARFLAGS) $@ $^


install: all
	install -d $(INCLUDEDIR)
	install -m 644 $(INC) $(INCLUDEDIR)
	install -d $(LIBDIR)
	install -m 644 libhash.a $(LIBDIR)

uninstall:
	$(RM) -r $(INCLUDEDIR)
	$(RM) $(LIBDIR)/libhash.a


tests/%.out: tests/%.c libhash.a
	$(CC) $(CFLAGS) $< libhash.a -o $@


test: all $(TSX)
	@for test_exec in $(TSX); do \
		echo "Running $$test_exec..."; \
		./$$test_exec || exit 1; \
	done


clean:
	$(RM) $(OBJ) libhash.a $(TSX)
