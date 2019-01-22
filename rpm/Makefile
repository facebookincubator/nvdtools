# /bin/sh uses dash and fails to expand curly braces otherwise
SHELL=/bin/bash

all:
	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	echo '%_topdir $(HOME)/rpmbuild' > ~/.rpmmacros
	make -C .. archive
	mv ../nvdtools-*.gz $(HOME)/rpmbuild/SOURCES
	cp nvdtools.spec $(HOME)/rpmbuild/SPECS
	cd $(HOME)/rpmbuild/SPECS
	rpmbuild -ba --define="_tag $(TRAVIS_TAG)" nvdtools.spec
