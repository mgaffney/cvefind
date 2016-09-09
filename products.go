package main

import (
	"bufio"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"unicode"
)

const url = "http://static.nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

type Title struct {
	Lang string `xml:"http://www.w3.org/XML/1998/namespace lang,attr,omitempty"`
	Val  string `xml:",chardata"`
}

type Item struct {
	Name   string  `xml:"name,attr"`
	Titles []Title `xml:"title"`
}

func (t Title) English() bool {
	if t.Lang == "en-US" {
		return true
	}
	return false
}

func (it Item) Key() string {
	// The CPE spec has a special meaning for items
	// suffixed with ':-' but CVEs do not seem
	// to use the suffix. This results in CVEs
	// not being shown. For example, Ruby on Rails 4.1.0
	// has the following key in the CPE dictionary:
	// 	  cpe:/a:rubyonrails:ruby_on_rails:4.1.0:-
	// But CVE-2015-3226 references Ruby on Rails 4.1.0
	// with the following CPE:
	//    cpe:/a:rubyonrails:ruby_on_rails:4.1.0
	return strings.TrimSuffix(it.Name, ":-")
}

func (it Item) Title() string {
	for _, v := range it.Titles {
		if v.English() {
			return strings.TrimSpace(v.Val)
		}
	}
	return ""
}

func ListProducts() {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	gzipReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	defer gzipReader.Close()
	dec := xml.NewDecoder(gzipReader)
	for {
		t, _ := dec.Token()
		if t == nil {
			break
		}
		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local == "cpe-item" {
				var it Item
				dec.DecodeElement(&it, &se)
				fmt.Printf("%s\t%s\n", it.Key(), it.Title())
			}
		}
	}
}

type Map struct {
	m map[string]string
}

func NewMap(r io.Reader) (*Map, error) {
	m := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		k, v := split(scanner.Text())
		m[k] = v
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading cpe input: %s", err)
	}
	return &Map{m}, nil
}

func split(s string) (string, string) {
	i := strings.IndexFunc(s, unicode.IsSpace)
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i:])
}

func (m Map) String() string {
	return fmt.Sprintf("%v", m.m)
}

func (m Map) Get(k string) (string, bool) {
	v, ok := m.m[k]
	return v, ok
}

func (m Map) FindAll(keys []string) []string {
	var values []string
	for _, k := range keys {
		if v, ok := m.m[k]; ok {
			values = append(values, v)
		}
	}
	return values
}
