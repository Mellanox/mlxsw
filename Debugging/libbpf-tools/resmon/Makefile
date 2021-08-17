# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
PACKAGE = resmon
REL_SRCDIR := ..
include $(REL_SRCDIR)/common.mk

OUTPUT := .output
INCLUDES := $(COMMON_INCLUDE)
APPS := resmon
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
	#
EXTRA_CLEAN :=			\
	$(OUTPUT)/config.h	\
	#
TESTS :=		\
	test.sh		\
	#

BUILT := $(APPS) $(SYSTEMD_UNITS)

.PHONY: all
all: $(BUILT)

.PHONY: $(APPS)
$(APPS): %: $(OUTPUT)/%

.PHONY: install
install: $(BUILT)
	$(call msg,MKDIR,$(RUNSTATEDIR))
	$(Q)$(INSTALL_DATA) -d -m 755 '$(DESTDIR)$(RUNSTATEDIR)'
	$(call do_install_program,$(APPS:%=$(OUTPUT)/%),$(BINDIR))
	$(call do_install_program,$(SYSTEMD_UNITS),$(SYSTEMDSYSTEMUNITDIR))

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
$(OUTPUT)/resmon: $(resmon-OBJECTS)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) -lz $^ -o $@

$(OUTPUT)/%.o: %.c resmon.h mlxsw.h $(COMMON_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OUTPUT)/resmon.o: $(OUTPUT)/config.h
$(OUTPUT)/resmon.o: INCLUDES += -I$(OUTPUT)

$(OUTPUT)/resmon-dl.o: INCLUDES += $(shell pkgconf --cflags libnl-3.0 \
				     libnl-genl-3.0)

$(OUTPUT)/%: %.in | $(OUTPUT)
	$(call msg,SED,$*)
	$(Q)sed -e '$(VAR_SUBSTITUTIONS)' $< > $@
	$(Q)chmod --reference=$< $@

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -f $(foreach tgt,$(APPS),$($(tgt)-OBJECTS))
	$(Q)rm -f $(APPS:%=$(OUTPUT)/%) $(SYSTEMD_UNITS) $(EXTRA_CLEAN)
	$(Q)if test -d $(OUTPUT); then rmdir $(OUTPUT); fi
