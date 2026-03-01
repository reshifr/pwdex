package main

import (
	"fmt"
	"os"

	"github.com/reshifr/pwdex/internal/possession"
)

func main() {
	config, err := possession.MakeConfig("key", "INI GILA SEKALI 😏🫵")
	if err != nil {
		fmt.Printf("pwdex: %s\n", err)
		os.Exit(1)
	}
	fmt.Println(config)
}
