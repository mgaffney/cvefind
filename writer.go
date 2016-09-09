package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"strings"
)

var printHeader bool

func init() {
	flag.BoolVar(&printHeader, "H", false, "print csv header row")
}

func writePerCVE(c <-chan CVE, w io.Writer) error {
	csv := csv.NewWriter(w)
	if printHeader {
		header := []string{
			"CVE ID",
			"Score (CVSS 2.0)",
			"Product Count",
			"Product List",
			"CVE Last Modified",
			"CVE Published",
			"Summary",
		}
		csv.Write(header)
	}
	for cve := range c {
		rec := []string{
			cve.Id,
			cve.Score,
			fmt.Sprint(len(cve.Products)),
			strings.Join(cve.Products, ", "),
			cve.Modified.String(),
			cve.Published.String(),
			cve.Summary,
		}
		csv.Write(rec)
	}
	csv.Flush()
	if err := csv.Error(); err != nil {
		return err
	}
	return nil
}
