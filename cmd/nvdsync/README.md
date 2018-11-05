# nvdsync

nvdsync is a command line tool for synchronizing vulnerability data feeds from NVD to a local directory: https://nvd.nist.gov/vuln/data-feeds

Currently supports CVE and CPE feeds.


## How it works

For CVE feeds, nvdsync downloads the .meta files provided by NVD and compare them to a local copy of the same file. If the local file does not exist or the contents are different, then it stores the remote .meta file locally and downloads the corresponding feed file. When new files are downloaded, nvdsync validates their SHA256 of the uncompressed data against what's in the .meta file.

CPE feeds do not offer a .meta file thus nvdsync relies on the web server's etag http response header to know it's time to sync the local feeds. If a .etag file does not exist in the local directory it creates one and downloads the CPE feed then subsequent runs use the .etag file.

By default, nvdsync does not print any information out, except errors. In order to get more information please us -v=1 flags in the command line.

## Proxy

nvdsync uses a standard http client that assumes it can access NVD (or the configured upstream host) directory. In order to use proxies please set the http_proxy or https_proxy environment variables.
