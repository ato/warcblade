package main

import (
	"fmt"
	"os"
)

func main() {
	if os.Args[1] == "get" {
		cmdGet(os.Args[2:])
	} else if os.Args[1] == "cdx" {
		cmdCdx(os.Args[2:])
	} else {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
	}
}


