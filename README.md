[![Build Status](https://api.travis-ci.com/facebookincubator/nvdtools.svg?branch=master)](https://travis-ci.com/facebookincubator/nvdtools)

# NVD Tools

A collection of tools for working with [National Vulnerability Database](https://nvd.nist.gov/) feeds.

The [HOWTO](HOWTO.md) provides a broader view on how to effectively use these tools.

---
* [Requirements](#requirements)
* [Installation](#installation)
* [Command line tools](#command-line-tools)
  * [cpe2cve](#cpe2cve)
  * [csv2cpe](#cpe2cve)
  * [rpm2cpe](#rpm2cpe)
  * [nvdsync](#nvdsync)
* [License](#license)
---

## Requirements

* Go 1.10 or newer

## Installation

You need a properly setup Go environment.

#### Download NVD Tools:

```bash
go get github.com/facebookincubator/nvdtools/...
```

#### Install all included command line tools:

```bash
cd "$GOPATH"/src/github.com/facebookincubator/nvdtools/cmd
go install ./...
```

## Command line tools

### cpe2cve

*cpe2cve* is a command line tool for scanning an inventory of CPE names for vulnerabilities.

It expects a stream of lines of delimiter-separated fields, one of these fields being a delimiter-separated list of CPE names in the inventory.

Vulnerability feeds should be provided as arguments to the program in XML or JSON format (configured by `-feed` flag).

Output is a stream of delimiter-separated input value decorated with a vulnerability ID (CVE) and a delimiter-separated list of CPE names that match this vulnerability.

Unwanted input fields could be erased from the output with `-e` option.

Input and output delimiters can be configured with `-d`, `-d2`, `-o` an `-o2` options.

The column to which output the CVE and matches for that CVE can be configured with `-cve` and `-matches` options correspondingly.

#### Example 1: scan a software for vulnerabilities

```bash
echo "cpe:/a:gnu:glibc:2.28" | cpe2cve -feed json -cpe 1 -e 1 -cve 1 nvdcve-1.0-*.json.gz
CVE-2009-4881
CVE-2015-8985
CVE-2014-5119
CVE-2016-3706
CVE-2016-4429
CVE-2016-3706
CVE-2016-4429
CVE-2010-3192
CVE-2010-4756
```

#### Example 2: find vulnerabilities in software inventory per production host

```bash
cat <<EOL | cpe2cve -feed json -d ' ' -d2 , -o ' ' -o2 , -cpe 2 -e 2 -matches 3 -cve 2 nvdcve-1.0-*.json.gz
host1.foo.bar cpe:/a:gnu:glibc:2.28,cpe:/a:gnu:zlib:1.2.8
host2.foo.bar cpe:/a:gnu:glibc:2.28,cpe:/a:haxx:curl:7.55.0
EOL
host1.foo.bar CVE-2009-4881 cpe:/a:gnu:glibc:2.28
host1.foo.bar CVE-2015-8985 cpe:/a:gnu:glibc:2.28
host1.foo.bar CVE-2014-5119 cpe:/a:gnu:glibc:2.28
host1.foo.bar CVE-2016-3706 cpe:/a:gnu:glibc:2.28
host1.foo.bar CVE-2016-4429 cpe:/a:gnu:glibc:2.28
host1.foo.bar CVE-2016-9840 cpe:/a:gnu:zlib:1.2.8
host1.foo.bar CVE-2016-9841 cpe:/a:gnu:zlib:1.2.8
host1.foo.bar CVE-2016-9842 cpe:/a:gnu:zlib:1.2.8
host1.foo.bar CVE-2016-9843 cpe:/a:gnu:zlib:1.2.8
host1.foo.bar CVE-2016-3706 cpe:/a:gnu:glibc:2.28
host1.foo.bar CVE-2016-4429 cpe:/a:gnu:glibc:2.28
host1.foo.bar CVE-2016-9840 cpe:/a:gnu:zlib:1.2.8
host1.foo.bar CVE-2016-9841 cpe:/a:gnu:zlib:1.2.8
host1.foo.bar CVE-2016-9842 cpe:/a:gnu:zlib:1.2.8
host1.foo.bar CVE-2016-9843 cpe:/a:gnu:zlib:1.2.8
host1.foo.bar CVE-2010-3192 cpe:/a:gnu:glibc:2.28
host1.foo.bar CVE-2010-4756 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2009-4881 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2015-8985 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2014-5119 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2016-3706 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2016-4429 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2018-1000007 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000120 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000121 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000122 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000301 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-0500 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000007 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000120 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000121 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000122 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000300 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2018-1000301 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2016-3706 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2016-4429 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2010-3192 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2010-4756 cpe:/a:gnu:glibc:2.28
host2.foo.bar CVE-2017-1000101 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2017-8816 cpe:/a:haxx:curl:7.55.0
host2.foo.bar CVE-2017-8817 cpe:/a:haxx:curl:7.55.0
```

### csv2cpe

*csv2cpe* is a tool that generates an URI-bound CPE from CSV input, flags configure the meaning of each input field:

  - `-cpe_part` -- identifies the class of a product: h for hardware, a for application and o for OS
  - `-cpe_vendor` -- identifies  the person or organisation that manufactured or created the product
  - `-cpe_product` -- describes or identifies the most common and recognisable title or name of the product
  - `-cpe_version` -- vendor-specific alphanumeric strings characterising the particular release version of the product
  - `-cpe_update` -- vendor-specific alphanumeric strings characterising the particular update, service pack, or point release of the product
  - `-cpe_edition` -- capture edition-related terms applied by the vendor to the product; this attribute is considered deprecated in CPE specification version 2.3 and it should be assigned the logical value ANY except where required for backward compatibility with version 2.2 of the CPE specification.
  - `-cpe_swedition` -- characterises how the product is tailored to a particular market or class of end users
  - `-cpe_targetsw` -- characterises the software computing environment within which the product operates
  - `-cpe_targethw` -- characterises the software computing environment within which the product operates
  - `-cpe_language` --  defines the language supported in the user interface of the product being described; must be valid language tags as defined by [RFC5646]
  - `-cpe_other` -- any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value

Omitted parts of the CPE name defaults to logical value ANY, as per [specification](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf)

Optional flag `-lower` brings the strings to lower case.

#### Example: generate URI-bound CPE name out of comma-separated list of attributes

```bash
$ echo 'a,Microsoft,Internet Explorer,8.1,SP1,-,*' | csv2cpe -x -lower -cpe_part=1 -cpe_vendor=2 -cpe_product=3 -cpe_version=4 -cpe_update=5 -cpe_edition=6 -cpe_language=7
cpe:/a:microsoft:internet_explorer:8.1:sp1:-
```

### rpm2cpe

*rpm2cpe* takes a delimiter-separated input with one of the fields containing RPM package name and produces delimiter-separated output consisting of the same fields plus CPE name parsed from RPM package name.

#### Example: generate URI-bound CPE name out of RPM package filename

```bash
echo openoffice-eu-writer-4.1.5-9789.i586.rpm | rpm2cpe -rpm=1 -cpe=2 -e=1
cpe:/a::openoffice-eu-writer:4.1.5:9789:~~~~i586~
```

### nvdsync

*nvdsync* synchronizes NVD data feeds to local directory; it  checks the hashes of the files against the ones provided by NVD and only updates the changed files; can sync both XML and JSON feeds (configurable).

#### Example: download NVD CVE feed in JSON to ~/feeds/json

```bash
nvdsync -v 1 -cve_feed=cve-1.0.json.gz ~/feeds/json
I0820 09:15:56.270696 1197925 cve.go:217] checking meta file "nvdcve-1.0-2002.meta" for updates to "nvdcve-1.0-2002.json.gz"
I0820 09:15:56.270713 1197925 cve.go:252] downloading meta file "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2002.meta"
I0820 09:16:01.847147 1197925 cve.go:217] checking meta file "nvdcve-1.0-2003.meta" for updates to "nvdcve-1.0-2003.json.gz"
I0820 09:16:01.847168 1197925 cve.go:252] downloading meta file "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2003.meta"

... 14 lines skipped ...

I0820 09:16:26.833321 1197925 cve.go:217] checking meta file "nvdcve-1.0-2011.meta" for updates to "nvdcve-1.0-2011.json.gz"
I0820 09:16:26.833346 1197925 cve.go:252] downloading meta file "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2011.meta"
I0820 09:16:29.316286 1197925 cve.go:267] data file "nvdcve-1.0-2011.json.gz" needs update in "/home/dvl/feeds/json": local{LastModifiedDate:2018-07-28 03:33:26 -0400
-0400 Size:201819657 ZipSize:9353214 GzSize:9353078 SHA256:AAEE78FB567FA96CC4A654C432414D98B741014A8A410E980F200127FD90F430} != remote{LastModifiedDate:2018-08-15 03:4
8:06 -0400 -0400 Size:202676227 ZipSize:9409647 GzSize:9409511 SHA256:585251B440C894CAC1C96C45800D00488AC9EE82A46998797627E4937839FE03}
I0820 09:16:29.316352 1197925 cve.go:311] downloading data file "https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-2011.json.gz"

... more lines skipped ...
```

### fireeye2nvd

*fireeye2nvd* downloads the vulnerability data from FireEye and converts it into NVD format. The resulting file can be used as a feed in cpe2cve processor

```bash
FIREEYE_PUBLIC=public_key
FIREEYE_PRIVATE=private_key
fireeye2nvd -since 1h > fireeye_vulns.json
2019/04/26 03:24:12 fireeye2nvd.go:70: Downloading since Fri, 26 Apr 2019 02:24:12 PDT
2019/04/26 03:24:12 vulnerability.go:19: Fetching: Start: (Fri, 26 Apr 2019 02:24:12 PDT); End: (Fri, 26 Apr 2019 03:24:12 PDT)
2019/04/26 03:24:13 vulnerability.go:24: Adding 2 vulns
```

## License

nvdtools licensed under Apache License, Version 2.0, as found in the [LICENSE](LICENSE) file.
