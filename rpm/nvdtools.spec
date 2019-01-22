Name:           nvdtools
Summary:        A collection of tools for working with National Vulnerability Database feeds.

Version:	%{_tag}
Release:	1
License:        Apache License 2.0
URL:            https://github.com/facebookincubator/nvdtools
Source0:	%{name}-%{version}.tar.gz	

BuildRoot:	%{_tmpdir}/%{name}-%{version}

%define _rpmdir ../release
%define _rpmfilename %%{NAME}-%%{VERSION}.%%{ARCH}.rpm

%description
A set of tools to work with the feeds (vulnerabilities, CPE dictionary etc.) distributed by National Vulnerability Database (NVD)

%prep
%setup -q

%build
make build

%install
make DESTDIR=%{buildroot} install

%files
%license LICENSE
%{_bindir}/cpe2cve
%{_bindir}/csv2cpe
%{_bindir}/nvdsync
%{_bindir}/rpm2cpe

%changelog
