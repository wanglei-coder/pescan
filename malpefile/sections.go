package malpefile

import "pescan/pe"

func (p *PEFile) Section() {
	//p.logger.Debug("start customSections...")

	customSections := make([]Section, 0, p.peFile.NtHeader.FileHeader.NumberOfSections)
	for _, section := range p.peFile.Sections {
		customSection := Section{
			Name:             section.NameString(),
			Rva:              Hex(uint64(section.Header.VirtualAddress)),
			VirtualSize:      Hex(uint64(section.Header.VirtualSize)),
			PointerToRawData: section.Header.PointerToRawData,
			SizeOfRawData:    section.Header.SizeOfRawData,
			Entropy:          section.Entropy,
			MD5:              getMD5(section.Data(0, 0, p.peFile)),
		}

		if section.Entropy > 7 {
			p.Data.IsPacked = true
		}

		customSections = append(customSections, customSection)
		p.Data.Info.CalculatedFileSize = getCalculatedFileSize(section)
	}
	p.Data.Sections = customSections

	//p.logger.Debugf("customSections end: %+v", customSections)
}

func getCalculatedFileSize(section pe.Section) int {
	return int(section.Header.VirtualAddress) + int(section.Header.VirtualSize)
}
