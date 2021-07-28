package malpefile

import "github.com/saferwall/pe"

func (p *PEFile) Export() {
	p.Data.Exports = getExports(p.peFile)

}

func getExports(peFile *pe.File) []*Export {
	if peFile.Export == nil {
		return nil
	}

	numberOfFunctions := peFile.Export.Struct.NumberOfFunctions
	if numberOfFunctions == 0 {
		return nil
	}

	addressBase := getImageBase(peFile)
	exportList := make([]*Export, 0, numberOfFunctions)
	for _, exp := range peFile.Export.Functions {
		address := addressBase + uint64(exp.FunctionRVA)
		export := &Export{
			Ordinal: exp.Ordinal,
			Name:    exp.Name,
			Address: Hex(address),
		}
		exportList = append(exportList, export)
	}
	return exportList
}
