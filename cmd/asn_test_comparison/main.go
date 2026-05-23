package main

import (
	"fmt"
	"sort"

	"whitedns-go/internal/asn"
)

func main() {
	// Load ASN engine
	eng := asn.NewASNEngine(".")
	if err := eng.Load(); err != nil {
		fmt.Printf("Load error: %v\n", err)
	}

	testASNs := []string{"AS13335", "AS58224", "AS209242"}

	fmt.Println("GO ASN NETWORK COUNTS")
	fmt.Println("============================================================")

	for _, targetASN := range testASNs {
		// Get all groups and find matching ASN
		groups, _ := eng.SearchGroups("*")

		var networks []string
		for _, group := range groups {
			if group.ASN == targetASN {
				networks = group.CIDRs
				break
			}
		}

		fmt.Printf("%s: %d networks\n", targetASN, len(networks))

		// Show first few
		if len(networks) <= 5 {
			for _, net := range networks {
				fmt.Printf("  %s\n", net)
			}
		} else {
			sort.Strings(networks)
			for _, net := range networks[:3] {
				fmt.Printf("  %s\n", net)
			}
			fmt.Printf("  ... (%d more)\n", len(networks)-3)
		}
	}
}
