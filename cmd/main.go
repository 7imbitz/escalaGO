package main

import (
	"cmd/core"
	"fmt"
	"runtime"

	"github.com/projectdiscovery/gologger"
)

func main() {
	core.ShowBanner()
	//CHECK OS
	os := runtime.GOOS
	switch os {
	case "linux":
		gologger.Info().Msg("OS is linux, running for linux PE.")
		core.LinPrivEscChecker()
	case "window":
		fmt.Println("Running on Window")
		//TODO
	}
}
