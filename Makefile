# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of nvme.
# Copyright (c) 2021 Dell Inc.
#
# Authors: Martin Belanger <Martin.Belanger@dell.com>
#
NAME          := nvme
.DEFAULT_GOAL := ${NAME}
BUILD-DIR     := .build
VERSION       := 2.3

${BUILD-DIR}:
	meson $@
	@echo "Configuration located in: $@"
	@echo "-------------------------------------------------------"

.PHONY: ${NAME}
${NAME}: ${BUILD-DIR}
	ninja -C ${BUILD-DIR}

.PHONY: clean
clean:
ifneq ("$(wildcard ${BUILD-DIR})","")
	ninja -C ${BUILD-DIR} -t $@
endif

.PHONY: purge
purge:
ifneq ("$(wildcard ${BUILD-DIR})","")
	rm -rf ${BUILD-DIR}
	rm -f nvme-cli-${VERSION}.tar*
endif

.PHONY: install dist
install dist: ${BUILD-DIR}
	cd ${BUILD-DIR} && meson $@

.PHONY: uninstall
uninstall:
	cd ${BUILD-DIR} && meson --internal uninstall

.PHONY: test
test: ${BUILD-DIR}
	ninja -C ${BUILD-DIR} $@

.PHONY: rpm
rpm: ${BUILD-DIR}
	git archive --format=tar HEAD > nvme-cli-${VERSION}.tar
	tar rf nvme-cli-${VERSION}.tar ${BUILD-DIR}/nvme-cli.spec
	gzip -f -9 nvme-cli-${VERSION}.tar
	rpmbuild -ta nvme-cli-${VERSION}.tar.gz -v

.PHONY: debug
debug:
	meson ${BUILD-DIR} --buildtype=debug
	ninja -C ${BUILD-DIR}
