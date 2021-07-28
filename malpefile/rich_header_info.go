package malpefile

import "github.com/saferwall/pe"

func (p *PEFile) RichHeaderInfo() {
	p.Data.RichHeaderInfo = getRichHeaderInfo(p.peFile)
}

func getRichHeaderInfo(p *pe.File) []*RichHeaderInfo {
	numberOfCompID := len(p.RichHeader.CompIDs)
	if numberOfCompID == 0 {
		return nil
	}

	richHeaderInfoList := make([]*RichHeaderInfo, 0, numberOfCompID)
	for _, compID := range p.RichHeader.CompIDs {
		richHeaderInfo := &RichHeaderInfo{
			ToolID:    compID.ProdID,
			Version:   compID.MinorCV,
			TimesUsed: compID.Count,
		}
		richHeaderInfoList = append(richHeaderInfoList, richHeaderInfo)
	}
	return richHeaderInfoList
}
