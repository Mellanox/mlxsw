# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
PACKAGE = resmon
REL_SRCDIR := ..
include $(REL_SRCDIR)/common.mk

OUTPUT := .output
INCLUDES := $(COMMON_INCLUDE)
CFLAGS := -g -Wall -Wunused

APPS := resmon resmon-exporter
resmon-OBJECTS :=		\
	$(OUTPUT)/resmon.o	\
	$(OUTPUT)/resmon-back.o	\
	$(OUTPUT)/resmon-c.o	\
	$(OUTPUT)/resmon-d.o	\
	$(OUTPUT)/resmon-dl.o	\
	$(OUTPUT)/resmon-jrpc.o	\
	$(OUTPUT)/resmon-reg.o	\
	$(OUTPUT)/resmon-sock.o	\
	$(OUTPUT)/resmon-stat.o	\
	#
SYSTEMD_UNITS :=				\
	$(OUTPUT)/resmon.service		\
	$(OUTPUT)/resmon-exporter.service	\
	#
EXTRA_CLEAN :=			\
	$(OUTPUT)/config.h	\
	$(OUTPUT)/resmon.bpf.o	\
	$(OUTPUT)/resmon.skel.h	\
	#
TESTS :=		\
	test.sh		\
	#
MAN_PAGES :=				\
	$(OUTPUT)/resmon.8		\
	$(OUTPUT)/resmon-exporter.8	\
	$(OUTPUT)/resmon-start.8	\
	$(OUTPUT)/resmon-stop.8		\
	$(OUTPUT)/resmon-ping.8		\
	$(OUTPUT)/resmon-stats.8	\
	$(OUTPUT)/resmon-emad.8		\
	$(OUTPUT)/resmon-dump.8		\
	#

BUILT := $(APPS) $(SYSTEMD_UNITS) $(MAN_PAGES)

.PHONY: all
all: $(BUILT)

.PHONY: doc
doc: $(MAN_PAGES)

.PHONY: $(APPS)
$(APPS): %: $(OUTPUT)/%

.PHONY: install
install: $(BUILT)
	$(call msg,MKDIR,$(RUNSTATEDIR))
	$(Q)$(INSTALL_DATA) -d -m 755 '$(DESTDIR)$(RUNSTATEDIR)'
	$(call do_install_program,$(APPS:%=$(OUTPUT)/%),$(BINDIR))
	$(call do_install_data,$(SYSTEMD_UNITS),$(SYSTEMDSYSTEMUNITDIR))
	$(call do_install_data,$(MAN_PAGES),$(MAN8DIR))
	$(call do_install_data,README.md,$(DOCDIR))

.PHONY: test
test: $(TESTS:%=run-%)

run-%: % $(APPS)
	$(call msg,RUN,$*)
	$(Q)./$*

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(OUTPUT)/resmon: CFLAGS += $(shell pkgconf --libs libelf json-c libsystemd \
				libnl-3.0 libnl-genl-3.0)
$(OUTPUT)/resmon: $(resmon-OBJECTS) $(LIBBPF_OBJ) $(COMMON_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $^ $(CFLAGS) -lz -o $@

$(OUTPUT)/%.o: %.c resmon.h mlxsw.h $(COMMON_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/resmon.o: $(OUTPUT)/config.h
$(OUTPUT)/resmon.o: INCLUDES += -I$(OUTPUT)

$(OUTPUT)/resmon-dl.o: INCLUDES += $(shell pkgconf --cflags libnl-3.0 \
				     libnl-genl-3.0)

$(OUTPUT)/resmon.bpf.o: INCLUDES += $(LIBBPF_INCLUDE)
$(OUTPUT)/resmon.bpf.o: resmon.bpf.c resmon.h ../common/vmlinux.h
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

$(OUTPUT)/resmon-back.o: INCLUDES += $(LIBBPF_INCLUDE) -I$(OUTPUT)
$(OUTPUT)/resmon-back.o: $(OUTPUT)/resmon.skel.h

%.skel.h: %.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/%: %.in | $(OUTPUT)
	$(call msg,SED,$*)
	$(Q)sed -e '$(VAR_SUBSTITUTIONS)' $< > $@
	$(Q)chmod --reference=$< $@

$(MAN_PAGES): $(OUTPUT)/%: %.md | $(OUTPUT)
	pandoc --standalone --to man $< -o $@

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -f $(foreach tgt,$(APPS),$($(tgt)-OBJECTS))
	$(Q)rm -f $(APPS:%=$(OUTPUT)/%) $(SYSTEMD_UNITS) $(MAN_PAGES) $(EXTRA_CLEAN)
	$(Q)if test -d $(OUTPUT); then rmdir $(OUTPUT); fi
