package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

var listProducts bool

func init() {
	flag.BoolVar(&listProducts, "l", false, "list all products in the CVE database")
}

func main() {
	log.SetOutput(os.Stderr)
	flag.Usage = usage
	flag.Parse()
	switch {
	case listProducts:
		ListProducts()
	default:
		FindCVEs(loadMap())
	}
}

func loadMap() *Map {
	var inputs []io.Reader
	if flag.NArg() == 0 {
		inputs = append(inputs, os.Stdin)
	}
	for _, fn := range flag.Args() {
		file, err := os.Open(fn)
		if err != nil {
			log.Fatal(err)
		}
		inputs = append(inputs, file)
		defer file.Close()
	}
	m, err := NewMap(io.MultiReader(inputs...))
	if err != nil {
		log.Fatal(err)
	}
	return m
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, strings.TrimSpace(ShortUsage))
	fmt.Fprintln(w, "\nOptions:")
	flag.PrintDefaults()
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, strings.TrimSpace(LongUsage))
}

func usage() {
	printUsage(os.Stderr)
	os.Exit(2)
}
