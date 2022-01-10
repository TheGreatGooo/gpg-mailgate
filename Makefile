PYTHON = python3.8

.PHONY: test unittest pre-clean clean

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
