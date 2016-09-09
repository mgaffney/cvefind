package main

var ShortUsage = `
Usage: cvefind [options] [file ...]   find CVEs for the products in the named files
   or: cvefind [options]              find CVEs for the products read from stdin
   or: cvefind -l                     list all products in the CVE database
`

var LongUsage = `
DESCRIPTION
cvefind finds CVEs for a list of products. Output is in CSV format.

INPUT
One product per line. A line begins with an ID followed by a whitespace then
text. All text after the whitespace until the EOL is the Product Name. The ID is
a CPE 2.2 URN. You can use 'cvefind -l' to create the input file.

OUTPUT
CSV format with the following columns:
 * CVE ID
 * Score (CVSS 2.0) - A range between 0.0 and 10.0
 * Product Count - The number of products vulnerable
 * Product List - The products vulnerable
 * CVE Last Modified - Timestamp
 * CVE Published - Timestamp
 * Summary - Description of the CVE

Use the '-H' option to output a Header in the first row.

EXAMPLES
List of all CVEs newly reported or modified in the last eight days:
	cvefind -l | cvefind

List of all CVEs newly reported in the last eight days:
	cvefind -l | cvefind -n

List of all CVEs ever reported (don't do this):
	cvefind -l | cvefind -a

TERMS
 * CPE  - Common Platform Enumeration
 * CVE  - Common Vulnerabilities and Exposures
 * CVSS - Common Vulnerability Scoring System
 * CSV  - Comma-separated values

URLs
-l = http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
-m = https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz
-n = https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.gz
-a = https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2003.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2004.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2005.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2006.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2007.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2008.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2009.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2010.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2011.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2012.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2013.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2014.xml.gz
     https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2015.xml.gz
     plus one for each year after 2015 up to the current year

MORE INFO
See https://nvd.nist.gov/download.cfm for more information.
`
