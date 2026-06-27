package ui

import (
	"whitedns-go/internal/asn"
	"whitedns-go/internal/asnexport"
)

func defaultASNExportPath(dataDir string) string {
	return asnexport.DefaultExportPath(dataDir)
}

func exportASNTargetsToTXT(dataDir string, targets []string, outputPath string) (string, int, error) {
	return asnexport.ExportTargetsToTXT(dataDir, targets, outputPath)
}

func exportASNGroupsToTXT(dataDir string, groups []asn.ASNGroup, outputPath string) (string, int, error) {
	cidrs := make([]string, 0)
	for _, group := range groups {
		cidrs = append(cidrs, group.CIDRs...)
	}
	return asnexport.ExportTargetsToTXT(dataDir, cidrs, outputPath)
}
