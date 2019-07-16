OVAL_URL=https://people.canonical.com/~ubuntu-security/oval
TOX_ARGS?=
PHONY: run get_oval

env:
	virtualenv -p python3.6 $@

get_oval: com.ubuntu.bionic.cve.oval.xml

com.ubuntu.bionic.cve.oval.xml:
	wget $(OVAL_URL)/$@.bz2
	bunzip2 $@.bz2

rerun:
	rm .docker || true
	make .docker
	make run

interactive:
	ipython -i ipython/preload.py

test_skipslow:
	make TOX_ARGS=--skipslow test

test:
	tox -- $(TOX_ARGS)
