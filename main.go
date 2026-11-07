package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"my-zerotier/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "Fehler:", err)
		os.Exit(1)
	}
}
