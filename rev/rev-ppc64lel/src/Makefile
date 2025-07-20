#
# @mebeim - 2025-04-06
#
CHALL_NAME     := PPC64LEL
ARCHIVE        := $(CHALL_NAME).tar.gz
ARCHIVE_TOPDIR := $(CHALL_NAME)

TARGET       := powerpc64le-linux-gnu
CROSS_PREFIX := $(TARGET)-

CC    := $(CROSS_PREFIX)gcc
STRIP := $(CROSS_PREFIX)strip

SRCDIR := src
OUTDIR := build
BINARY := $(OUTDIR)/$(CHALL_NAME)
SRCS   := $(wildcard $(SRCDIR)/*.c)
OBJS   := $(SRCS:$(SRCDIR)/%.c=$(OUTDIR)/%.o)

FLAG_KEY      := deada550b8265a7859cf07f7ad97340f0ae282f84022393c251e5b05385f29a2720487da2230f6287f1fcb4fa1f91020
VERIFIER_SEED := 97a13e22262c043a
VERIFIER_C    := $(OUTDIR)/verifier.c
VERIFIER_H    := $(OUTDIR)/verifier.h
VERIFIER_O    := $(OUTDIR)/verifier.o

OBJS += $(VERIFIER_O)
DEPS := $(OBJS:.o=.d)

LIBSODIUM_DIR := $(OUTDIR)/libsodium
LIBSODIUM_SRC := $(OUTDIR)/libsodium/libsodium-1.0.18
LIBSODIUM_L   := $(LIBSODIUM_SRC)/src/libsodium/.libs
LIBSODIUM_SO  := $(LIBSODIUM_L)/libsodium.so.23
LIBSODIUM_URL := 'https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz'

CFLAGS  := -std=gnu11 -Wall -Wextra -O2 -MMD -I$(SRCDIR) -I$(OUTDIR)
LDFLAGS := -no-pie -fno-pie -L$(LIBSODIUM_L)
LDLIBS  := -lsodium

ifeq ($(TEST),1)
CFLAGS += -DTEST
endif

ifneq ($(V),1)
MAKEFLAGS += -s
endif

.DEFAULT_GOAL := $(BINARY)

-include $(DEPS)


$(BINARY): $(OBJS) $(LIBSODIUM_SO) bswap_funcs.py | $(OUTDIR)
	@echo 'CCLD      $@'
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
	cp $@ $@.orig

ifneq ($(TEST),1)
	@echo 'BSWAP     $@'
ifeq ($(V),1)
	./bswap_funcs.py $@
else
	./bswap_funcs.py $@ >/dev/null
endif
endif

ifneq ($(DEBUG),1)
	@echo 'STRIP     $@'
	$(STRIP) $@
endif

# Need to generate verifier.h before any .o that needs it
$(OUTDIR)/main.o: $(VERIFIER_H)

$(VERIFIER_C) $(VERIFIER_H): gen_verifier.py | $(OUTDIR)
	@echo 'GEN       $@'
	./gen_verifier.py $(VERIFIER_C) $(VERIFIER_H) $(FLAG_KEY) $(VERIFIER_SEED)

$(VERIFIER_O): $(VERIFIER_C) $(VERIFIER_H) | $(OUTDIR)
	@echo 'CC        $@'
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR)/%.o: $(SRCDIR)/%.c | $(OUTDIR)
	@echo 'CC        $@'
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUTDIR):
	@echo 'MKDIR     $@'
	mkdir -p $@


$(LIBSODIUM_SRC): | $(LIBSODIUM_DIR)
	@echo 'WGET      libsodium-1.0.18.tar.gz'
	wget -q -O- $(LIBSODIUM_URL) | tar -C $(LIBSODIUM_DIR) -zxf-

$(LIBSODIUM_SO): $(LIBSODIUM_SRC)
	@echo '--- Building libsodium ---------------'
	cd $(LIBSODIUM_SRC) && ./configure --host=$(TARGET)
	$(MAKE) -C $(LIBSODIUM_SRC)
	@echo '--- Building libsodium OK ------------'

$(LIBSODIUM_DIR):
	@echo 'MKDIR     $@'
	mkdir -p $@


archive: $(ARCHIVE)
.PHONY: archive

$(ARCHIVE): $(BINARY) $(LIBSODIUM_SO) PLAYER_README.md | $(ARCHIVE_TOPDIR)
	@echo 'ARCHIVE   $(ARCHIVE)'
	mkdir -p $(ARCHIVE_TOPDIR)

	cp $(BINARY) $(LIBSODIUM_SO) $(ARCHIVE_TOPDIR)
	cp PLAYER_README.md $(ARCHIVE_TOPDIR)/README.md

	tar -czf $(ARCHIVE) $(ARCHIVE_TOPDIR)
	rm -rf $(ARCHIVE_TOPDIR)

$(ARCHIVE_TOPDIR):
	@echo 'MKDIR     $@'
	mkdir -p $@

clean:
	@echo CLEAN
	rm -f $(BINARY) $(OBJS) $(DEPS) $(VERIFIER_C) $(VERIFIER_H)
.PHONY: clean

distclean:
	@echo DISTCLEAN
	rm -fr $(OUTDIR)
.PHONY: distclean
