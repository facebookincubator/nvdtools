# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOGET=$(GOCMD) get
CPE2CVE=cpe2cve
CSV2CPE=csv2cpe
NVDSYNC=nvdsync
RPM2CPE=rpm2cpe

VERSION=$(TRAVIS_TAG)
NAME=nvdtools
PKG=$(NAME)-$(VERSION)
TGZ=$(PKG).tar.gz

all: build 
build: 
	$(GOBUILD) -o $(CPE2CVE) ./cmd/$(CPE2CVE)/cpe2cve.go
	$(GOBUILD) -o $(CSV2CPE) ./cmd/$(CSV2CPE)/csv2cpe.go
	$(GOBUILD) -o $(NVDSYNC) ./cmd/$(NVDSYNC)/main.go
	$(GOBUILD) -o $(RPM2CPE) ./cmd/$(RPM2CPE)/rpm2cpe.go

clean: 
	$(GOCLEAN)
	rm -f $(CPE2CVE)
	rm -f $(CSV2CPE)
	rm -f $(NVDSYNC)
	rm -f $(RPM2CPE)
    
install:
	install -d $(DESTDIR)/usr/bin
	install -p -m 0755 ./cpe2cve $(DESTDIR)/usr/bin/cpe2cve
	install -p -m 0755 ./csv2cpe $(DESTDIR)/usr/bin/csv2cpe
	install -p -m 0755 ./nvdsync $(DESTDIR)/usr/bin/nvdsync
	install -p -m 0755 ./rpm2cpe $(DESTDIR)/usr/bin/rpm2cpe	 

archive:
	touch $(TGZ)
	tar czf $(TGZ) --exclude=$(TGZ) --transform s/$(NAME)/$(PKG)/ ../$(NAME)
