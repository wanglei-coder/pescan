package malpefile

import (
	"pescan/pe"
)

func (p *PEFile) ExportsModuleName() {
	p.Data.ExportsModuleName = getExportsModuleName(p.peFile)
}

func getExportsModuleName(peFile *pe.File) string {
	if peFile.Export == nil {
		return ""
	}
	return peFile.Export.Name
}
