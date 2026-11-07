package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/schmidt-software/kinfold/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
