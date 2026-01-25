# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
SUBDIRS = \
	mariadb_trace

.PHONY: all $(SUBDIRS) clean
all: $(SUBDIRS)

$(SUBDIRS):
	@echo "  BUILD    $@"
	@$(MAKE) -C $@

clean:
	@echo "  CLEAN    all"
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean 2>/dev/null || true; done

.PHONY: help
help:
	@echo "  all"
	@echo "  clean"
	@for dir in $(SUBDIRS); do echo "  $$dir"; done

