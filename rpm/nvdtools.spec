Name:           nvdtools
Version:        1.0
Release:        1
Summary:        A collection of tools for working with National Vulnerability Database feeds.

License:        Apache License 2.0
URL:            https://github.com/facebookincubator/nvdtools
Source0:	%{name}-%{version}.tar.gz	

BuildRoot:	%{_tmpdir}/%{name}-%{version}-%{release}

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
