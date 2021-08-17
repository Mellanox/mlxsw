# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
SAVE_DEFAULT_GOAL := $(.DEFAULT_GOAL)
TOP_SRCDIR := $(abspath $(REL_SRCDIR))

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= $(TOP_SRCDIR)/tools/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

INSTALL = install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644

PREFIX = /usr/local
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DATADIR = $(DATAROOTDIR)
SYSCONFDIR = $(PREFIX)/etc
LOCALSTATEDIR = $(PREFIX)/var
RUNSTATEDIR = $(LOCALSTATEDIR)/run
DOCDIR = $(DATAROOTDIR)/doc/$(PACKAGE)
MANDIR = $(DATAROOTDIR)/man
MAN8DIR = $(MANDIR)/man8
SYSTEMDSYSTEMUNITDIR = $(shell pkgconf --variable=systemdsystemunitdir systemd)
DESTDIR =

VAR_SUBSTITUTIONS = 				\
	s|@BINDIR@|$(BINDIR)|g;			\
	s|@SYSCONFDIR@|$(SYSCONFDIR)|g;		\
	s|@RUNSTATEDIR@|$(RUNSTATEDIR)|g;	\
	#

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	NQ = @
	msg =
else
	Q = @
	NQ =
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

LIBBPF_OUTPUT := $(TOP_SRCDIR)/.libbpf-output
LIBBPF_INCLUDE := -I$(LIBBPF_OUTPUT)
LIBBPF_OBJ := $(abspath $(LIBBPF_OUTPUT)/libbpf.a)
LIBBPF_SRC := $(TOP_SRCDIR)/libbpf/src

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) \
		| $(LIBBPF_OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

$(LIBBPF_OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

COMMON_OUTPUT := $(TOP_SRCDIR)/common/.output
COMMON_INCLUDE := -I$(TOP_SRCDIR)/common
COMMON_OBJ := $(COMMON_OUTPUT)/libcommon.a
COMMON_SRC := $(TOP_SRCDIR)/common

$(COMMON_OBJ): $(LIBBPF_OBJ)
	$(Q)$(MAKE) -C $(COMMON_SRC)

# delete failed targets
.DELETE_ON_ERROR:

# keep the libbpf intermediate target
.SECONDARY:

define __do_install
	$(call msg,INSTALL,$1)
	$(Q)if [ ! -d '$(DESTDIR)$2' ]; then		\
		$4 -d -m 755 '$(DESTDIR)$2';	\
	fi;
	$(Q)$4 $(if $3,-m $3,) $1 '$(DESTDIR)$2'
endef

define do_install_program
	$(call __do_install,$1,$2,$3,$(INSTALL_PROGRAM))
endef

define do_install_data
	$(call __do_install,$1,$2,$3,$(INSTALL_DATA))
endef

# To avoid picking up the above rules as default goal, revert back to the
# goal that we've had at the top of the file.
.DEFAULT_GOAL := $(SAVE_DEFAULT_GOAL)
