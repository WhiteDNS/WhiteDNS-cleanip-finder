package main

import (
	"fmt"
	"os"
	"path/filepath"

	"whitedns-go/internal/asn"
)

func main() {
	// Use current working directory as dataDir
	wd, _ := os.Getwd()
	// If running from project root, dataDir should be go-port
	dataDir := wd
	// Instantiate engine
	eng := asn.NewASNEngine(dataDir)
	if err := eng.Load(); err != nil {
		fmt.Printf("ASN Load warning: %v\n", err)
	}

	v4, v6 := eng.GetStats()
	groups, err := eng.SearchGroups("*")
	if err != nil {
		fmt.Printf("SearchGroups error: %v\n", err)
	}

	totalSubnets := 0
	for _, g := range groups {
		totalSubnets += g.SubnetCount
	}

	fmt.Printf("Go ASN stats:\n")
	fmt.Printf(" v4 entries (networks): %d\n", v4)
	fmt.Printf(" v6 entries (networks): %d\n", v6)
	fmt.Printf(" unique ASNs: %d\n", len(groups))
	fmt.Printf(" total subnets from groups: %d\n", totalSubnets)

	// Also print path used
	fmt.Printf(" data dir: %s\n", filepath.Dir(wd))
}
