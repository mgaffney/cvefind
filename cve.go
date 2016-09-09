package main

import "time"

type CVE struct {
	Id        string
	Summary   string
	Products  []string
	Score     string
	Published time.Time
	Modified  time.Time
}

type xMetrics struct {
	Score string `xml:"http://scap.nist.gov/schema/cvss-v2/0.2 score"`
}

type xCvss struct {
	Metrics xMetrics `xml:"http://scap.nist.gov/schema/cvss-v2/0.2 base_metrics"`
}

type xList struct {
	Products []string `xml:"http://scap.nist.gov/schema/vulnerability/0.4 product"`
}

type xEntry struct {
	Id        string    `xml:"http://scap.nist.gov/schema/vulnerability/0.4 cve-id"`
	Summary   string    `xml:"http://scap.nist.gov/schema/vulnerability/0.4 summary"`
	Published time.Time `xml:"http://scap.nist.gov/schema/vulnerability/0.4 published-datetime"`
	Modified  time.Time `xml:"http://scap.nist.gov/schema/vulnerability/0.4 last-modified-datetime"`
	Cvss      xCvss     `xml:"http://scap.nist.gov/schema/vulnerability/0.4 cvss"`
	List      xList     `xml:"http://scap.nist.gov/schema/vulnerability/0.4 vulnerable-software-list"`
}

func (e xEntry) CVE(p []string) CVE {
	c := CVE{
		Id:        e.Id,
		Summary:   e.Summary,
		Products:  p,
		Score:     e.Cvss.Metrics.Score,
		Published: e.Published,
		Modified:  e.Modified,
	}

	return c
}

// Sample of XML
/*

<entry id="CVE-2015-1840">
    <vuln:cve-id>CVE-2015-1840</vuln:cve-id>
    <vuln:summary>jquery_ujs.js in jquery-rails before 3.1.3 and 4.x before 4.0.4 and rails.js in jquery-ujs before 1.0.4, as used with Ruby on Rails 3.x and 4.x, allow remote attackers to bypass the Same Origin Policy, and trigger transmission of a CSRF token to a different-domain web server, via a leading space character in a URL within an attribute value.</vuln:summary>
	<vuln:vulnerable-software-list>
      <vuln:product>cpe:/a:rubyonrails:jquery-rails:4.0.0</vuln:product>
      <vuln:product>cpe:/a:rubyonrails:jquery-rails:4.0.1</vuln:product>
      <vuln:product>cpe:/a:rubyonrails:jquery-rails:3.1.2</vuln:product>
      <vuln:product>cpe:/a:rubyonrails:jquery-ujs:1.0.3</vuln:product>
    </vuln:vulnerable-software-list>
	<vuln:cvss>
      <cvss:base_metrics>
        <cvss:score>5.0</cvss:score>
        <cvss:access-vector>NETWORK</cvss:access-vector>
        <cvss:access-complexity>LOW</cvss:access-complexity>
        <cvss:authentication>NONE</cvss:authentication>
        <cvss:confidentiality-impact>PARTIAL</cvss:confidentiality-impact>
        <cvss:integrity-impact>NONE</cvss:integrity-impact>
        <cvss:availability-impact>NONE</cvss:availability-impact>
        <cvss:source>http://nvd.nist.gov</cvss:source>
        <cvss:generated-on-datetime>2015-07-27T08:26:32.747-04:00</cvss:generated-on-datetime>
      </cvss:base_metrics>
    </vuln:cvss>
    <vuln:published-datetime>2015-07-26T18:59:00.070-04:00</vuln:published-datetime>
    <vuln:last-modified-datetime>2015-08-25T22:01:00.360-04:00</vuln:last-modified-datetime>
</entry>

*/
