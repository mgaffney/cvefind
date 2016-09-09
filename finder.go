package main

import (
	"compress/gzip"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// URLs where CVEs are published. See https://nvd.nist.gov/download.cfm for
// more information.
const (
	recent     = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Recent.xml.gz"   // New CVEs within last eight days. Updated every two hours.
	modified   = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-Modified.xml.gz" // New or modified CVEs within last eight days. Updated every two hours.
	historical = "https://nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%d.xml.gz"       // URL pattern for older CVEs. Replace %d with a year >= 2002.
)

// Variables for scope of search
var (
	searchAll      bool
	searchNew      bool
	searchModified bool
)

func init() {
	flag.BoolVar(&searchAll, "a", false, "search all CVEs records (2002 up to now)")
	flag.BoolVar(&searchNew, "n", false, "search for new CVEs (within the last eight days)")
	flag.BoolVar(&searchModified, "m", true, "search for new or modified CVEs (within the last eight days)")
}

type sinker func(c <-chan CVE, w io.Writer) error

var sink = writePerCVE

func FindCVEs(m *Map) {
	done := make(chan struct{})
	defer close(done)
	c, errc := findCVEs(done, m, feeds())
	if err := sink(c, os.Stdout); err != nil {
		log.Fatal(err)
	}
	if err := <-errc; err != nil {
		log.Fatal(err)
	}
}

func feeds() []string {
	switch {
	case searchAll:
		return archiveURLs(2002, time.Now().Year())
	case searchNew:
		return []string{recent}
	case searchModified:
		return []string{modified}
	}
	return []string{}
}

func archiveURLs(startYear, endYear int) []string {
	var urls []string
	for i := startYear; i < endYear+1; i++ {
		urls = append(urls, fmt.Sprintf(historical, i))
	}
	return urls
}

// findCVEs starts goroutines to fetch the NVD XML Vulnerability Feeds in the urls.
func findCVEs(done <-chan struct{}, m *Map, urls []string) (<-chan CVE, <-chan error) {
	c := make(chan CVE)
	errc := make(chan error, 1)
	go func() {
		var wg sync.WaitGroup
		// For each url ...
		for _, url := range urls {
			wg.Add(1)
			// ... start a goroutine which ...
			go func(u string) {
				defer wg.Done()
				// ... retrieves ...
				resp, err := http.Get(u)
				if err != nil {
					errc <- err
					return
				}
				defer resp.Body.Close()

				// ... the gzipped ...
				gzipReader, err := gzip.NewReader(resp.Body)
				if err != nil {
					errc <- err
					return
				}
				defer gzipReader.Close()

				// ... XML file.
				dec := xml.NewDecoder(gzipReader)

				// The XML files can be very large, so don't read
				// the whole XML document into memory. Instead, ...
				for {
					t, err := dec.Token()
					if err == io.EOF {
						break
					}
					if err != nil {
						errc <- err
						return
					}
					switch se := t.(type) {
					case xml.StartElement:
						// ... process each CVE entry one at a time ...
						if se.Name.Local == "entry" {
							var xe xEntry
							dec.DecodeElement(&xe, &se)
							prods := m.FindAll(xe.List.Products)
							// ... if a CVE is for one of the products
							// we are interested in ...
							if len(prods) > 0 {
								select {
								case c <- xe.CVE(prods): // ... send the CVE on c
								case <-done:
									return
								}
							}
						}
					}
					// The XML documents can be really large,
					// so check if done is closed before going to
					// the next token.
					select {
					case <-done:
						break
					default:
					}
				}
			}(url)
		}

		// The url loop has exited, so all calls to wg.Add are done.
		// Start a goroutine to close c once all the sends are done.
		go func() {
			wg.Wait()
			close(c)
		}()
		close(errc)
	}()
	return c, errc
}
