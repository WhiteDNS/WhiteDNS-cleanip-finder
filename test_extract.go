package main

import (
	"fmt"

	"whitedns-go/internal/scanner"
)

func main() {
	// Test case with actual user input
	testInput := `217.214.40.196
194.225.208.35
217.214.40.211
185.208.79.149
91.198.110.197
217.114.50.83
45.92.93 112
185.208.79.107
2.144.6.3
2.144.6.240
217.114.40.83
2.144.6.184`

	// Test the parsing
	stats := scanner.ParseTargetsFromPaste(testInput)

	fmt.Printf("Input IPs: %d lines\n\n", len(testInput))
	fmt.Printf("Total parsed: %d\n", stats.Total)
	fmt.Printf("Valid IPs: %d\n", len(stats.Valid))
	fmt.Printf("Invalid: %d\n\n", len(stats.Invalid))

	fmt.Println("Valid IPs:")
	for i, ip := range stats.Valid {
		fmt.Printf("  %d. %s\n", i+1, ip)
	}

	if len(stats.Invalid) > 0 {
		fmt.Println("\nInvalid entries:")
		for i, invalid := range stats.Invalid {
			fmt.Printf("  %d. %s\n", i+1, invalid)
		}
	}
}
