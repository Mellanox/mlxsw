# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
REL_SRCDIR := .
include $(REL_SRCDIR)/common.mk

DIRS = common src

.PHONY: all
all: $(DIRS:%=build-%)

build-%:
	$(Q)$(MAKE) -C $*

.PHONY: clean
clean: $(DIRS:%=clean-%)
	$(call msg,CLEAN)
	$(Q)rm -rf $(LIBBPF_OUTPUT)

clean-%:
	$(Q)$(MAKE) -C $* clean
