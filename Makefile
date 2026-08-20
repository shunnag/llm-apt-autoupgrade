# aptai -- standard library only, so there is nothing to build.

PREFIX  ?= /usr/local
PYTHON  ?= python3

.PHONY: help test lint check install uninstall dry-run clean units

help:
	@echo "make test       run the test suite (no network, no root, no apt)"
	@echo "make lint       byte-compile every module and check the shell scripts"
	@echo "make check      lint + test"
	@echo "make install    install to \$$PREFIX ($(PREFIX)); needs root"
	@echo "make uninstall  remove the installed files; needs root"
	@echo "make dry-run    run the upgrade cycle without changing anything"
	@echo "make units      show the systemd unit files that would be installed"

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

lint:
	$(PYTHON) -m compileall -q aptai tests
	@command -v shellcheck >/dev/null 2>&1 && shellcheck scripts/*.sh || \
		(for f in scripts/*.sh; do sh -n "$$f" || exit 1; done; \
		 echo "shellcheck not installed; checked syntax with sh -n only")
	@command -v systemd-analyze >/dev/null 2>&1 && \
		systemd-analyze verify systemd/aptai.service systemd/aptai.timer || \
		echo "systemd-analyze not available; skipping unit verification"

check: lint test

install:
	PREFIX=$(PREFIX) ./scripts/install.sh

uninstall:
	PREFIX=$(PREFIX) ./scripts/uninstall.sh

dry-run:
	$(PYTHON) -m aptai --config config/aptai.toml run --dry-run --no-llm

units:
	@echo "--- systemd/aptai.service ---"; cat systemd/aptai.service
	@echo "--- systemd/aptai.timer ---"; cat systemd/aptai.timer

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
