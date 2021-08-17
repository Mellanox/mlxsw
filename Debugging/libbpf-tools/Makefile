# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
REL_SRCDIR := .
include $(REL_SRCDIR)/common.mk

DIRS = common src resmon

.PHONY: all
all: $(DIRS:%=build-%)

build-%:
	$(Q)$(MAKE) -C $*

.PHONY: install
install: install-resmon

install-%:
	$(Q)$(MAKE) -C $* install

.PHONY: test
test: test-resmon

test-%:
	$(Q)$(MAKE) -C $* test

.PHONY: doc
doc: doc-resmon

doc-%:
	$(Q)$(MAKE) -C $* doc

.PHONY: clean
clean: $(DIRS:%=clean-%)
	$(call msg,CLEAN)
	$(Q)rm -rf $(LIBBPF_OUTPUT)

clean-%:
	$(Q)$(MAKE) -C $* clean
