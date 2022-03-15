.POSIX:
.PHONY: test unittest pre-clean clean

#
# On systems where Python 3.x binary has a different name, just
# overwrite the name/path on the command line, like:
#
#     make test PYTHON=/usr/local/bin/python3.8
#
# This marco is passed via environment to test/e2e_test.py, where it's
# used to compute further commands.
#
PYTHON = python3

#
# Run a set of end-to-end tests.
#
# Test scenarios are described and configured by the test/e2e.ini
# file.  Basically this is just a script that feeds GPG Mailgate with
# known input and checks whether output meets expectations.
#
test: test/tmp test/logs pre-clean
	$(PYTHON) test/e2e_test.py

#
# Run unit tests
#
unittest:
	$(PYTHON) -m unittest discover -s test

pre-clean:
	rm -fv test/gpg-mailgate.conf
	rm -f test/logs/*.log

test/tmp:
	mkdir test/tmp

test/logs:
	mkdir test/logs

clean: pre-clean
	rm -rfv test/tmp test/logs
