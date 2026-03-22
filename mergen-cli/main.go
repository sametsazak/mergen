package main

import "github.com/sametsazak/mergen-cli/cmd"

// version is set at build time via -ldflags "-X main.version=x.y"
var version = "dev"

func main() {
	cmd.SetVersion(version)
	cmd.Execute()
}
