# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
REL_SRCDIR := ..
include $(REL_SRCDIR)/common.mk

OUTPUT := .output
INCLUDES := $(LIBBPF_INCLUDE)
LIBS := libcommon.a
libcommon.a-OBJECTS := \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/map_helpers.o \
	#

all: $(OUTPUT)/libcommon.a

$(OUTPUT)/libcommon.a: $(libcommon.a-OBJECTS)
	$(call msg,AR,$@)
	$(Q)ar cr $@ $^

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@
$(OUTPUT)/map_helpers.o: $(LIBBPF_OBJ)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(foreach tgt,$(LIBS),$($(tgt)-OBJECTS))
	$(Q)rm -f $(LIBS:%=$(OUTPUT)/%) $(EXTRA_CLEAN)
	$(Q)if test -d $(OUTPUT); then rmdir $(OUTPUT); fi
