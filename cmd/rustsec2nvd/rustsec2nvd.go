package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/facebookincubator/nvdtools/providers/rustsec"

	"github.com/golang/glog"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: rustsec2nvd <rustsec-crates-dir>")
		fmt.Println("Example:")
		fmt.Println("git clone https://github.com/RustSec/advisory-db")
		fmt.Println("rustsec2nvd advisory-db/crates > rustsec.cve.json")
		os.Exit(1)
	}

	feed, err := rustsec.Convert(os.Args[1])
	if err != nil {
		glog.Fatal(err)
	}

	err = json.NewEncoder(os.Stdout).Encode(feed)
	if err != nil {
		glog.Fatal(err)
	}
}
