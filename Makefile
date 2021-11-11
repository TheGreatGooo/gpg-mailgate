PYTHON = python2.7

.PHONY: test pre-clean clean

test: test/tmp test/logs pre-clean
	$(PYTHON) test/e2e_test.py

pre-clean:
	rm -fv test/gpg-mailgate.conf

test/tmp:
	mkdir test/tmp

test/logs:
	mkdir test/logs

clean: pre-clean
	rm -rfv test/tmp test/logs
