# cvefind utility

cvefind finds CVEs for a list of products. Output is in CSV format.

## Examples

List of all CVEs for Ruby on Rails newly reported or modified in the last eight days:
```
	cvefind -l | grep "[Rr]uby on [Rr]ails" | cvefind
```

List of all CVEs for Ruby on Rails newly reported in the last eight days:
```
	cvefind -l | grep "[Rr]uby on [Rr]ails" | cvefind -n
```

List of all CVEs for Ruby on Rails ever reported:
```
	cvefind -l | grep "[Rr]uby on [Rr]ails" | cvefind -a
```

Create a file with a list of products you want to monitor for CVEs on a
regular basis:
```
	cvefind -l | grep "[Rr]uby on [Rr]ails" > project-deps.txt
	cvefind -l | grep "[Gg]rails" >> project-deps.txt
```

Use the above file to find all CVEs ever reported for the products you
want to monitor:
```
	cvefind -a project-deps.txt > cve-list.csv
```

After the initial check, you can look for only newly reported CVEs as
part of a daily job:
```
	cvefind project-deps.txt > newly-reported-cve-list.csv
```

The output of `cvefind -l` can be edited in any text editor to further
refine the list of products you want to monitor.

## Building it

1. Install [go](http://golang.org/doc/install)
2. Run `go get github.com/mgaffney/cvefind`

## Running it

```
Usage: cvefind [options] [file ...]   find CVEs for the products in the named files
   or: cvefind [options]              find CVEs for the products read from stdin
   or: cvefind -l                     list all products in the CVE database
```

Run `cvefind -h` for more information.

## Input

One product per line. A line begins with an ID followed by a whitespace
then text. All text after the whitespace until the EOL is the Product
Name. The ID is a CPE 2.2 URN. You can use `cvefind -l` to create the
input file.

## Output

CSV format with the following columns:
 * CVE ID
 * Score (CVSS 2.0) - A range between 0.0 and 10.0
 * Product Count - The number of products vulnerable
 * Product List - The products vulnerable
 * CVE Last Modified - Timestamp
 * CVE Published - Timestamp
 * Summary - Description of the CVE

Use the `-H` option to output a Header in the first row.

## Terms

* CPE  - Common Platform Enumeration
* CVE  - Common Vulnerabilities and Exposures
* CVSS - Common Vulnerability Scoring System
* CSV  - Comma-separated values

## URLs

The URLs used per command line option:

`-l`
* http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz

`-m`
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz

`-n`
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.gz

`-a`
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2004.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2005.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2006.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2007.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2015.xml.gz
* https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2016.xml.gz
* plus one for each year after 2016 up to the current year

## More Info

All data is retrieved from the [National Vulnerability
Database](https://nvd.nist.gov) website.  See [NVD Data
Feeds](https://nvd.nist.gov/download.cfm) for more information about
each of the above URLs.

