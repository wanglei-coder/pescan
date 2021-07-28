package malpefile

import (
	"github.com/saferwall/pe"
)

func (p *PEFile) Import() {
	numberOfImport := len(p.peFile.Imports)
	if numberOfImport == 0 {
		return
	}

	addressBase := getImageBase(p.peFile)

	importList := make([]map[string][]Function, 0, numberOfImport)
	for _, imp := range p.peFile.Imports {
		functionList := make([]Function, 0, len(imp.Functions))
		for _, entry := range imp.Functions {
			address := addressBase + uint64(entry.ThunkRVA)
			function := Function{
				Name:    entry.Name,
				Address: Hex(address),
			}
			functionList = append(functionList, function)
		}
		importList = append(importList, map[string][]Function{imp.Name: functionList})
	}
	p.Data.Imports = importList
}

func getImageBase(peFile *pe.File) uint64 {
	if peFile.Is64 {
		OptionalHeader := peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader64)
		return OptionalHeader.ImageBase
	} else {
		OptionalHeader := peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader32)
		return uint64(OptionalHeader.ImageBase)
	}
}
