package core

import (
	"fmt"

	"github.com/projectdiscovery/gologger"
)

// Version is the current version of goGo-Dork
const Version = `1.0.0`

// Author of the tools
const Author = `7imbitz`

// goGo-Dork logo
var banner = fmt.Sprintf(`
                        __      __________ 
  ___  ______________ _/ /___ _/ ____/ __ \
 / _ \/ ___/ ___/ __ '/ / __ '/ / __/ / / /
/  __(__  ) /__/ /_/ / / /_/ / /_/ / /_/ / 
\___/____/\___/\__,_/_/\__,_/\____/\____/  
										 							  
                                     %s
`, Author)

// showBanner is used to show the banner to the user
func ShowBanner() {
	gologger.Print().Msgf("%s", banner)
	gologger.Info().Msgf("escalaGO version %s", Version)
	gologger.Info().Msg("A privilege escalation tools based on Top 10 TryHackMe.")
}
