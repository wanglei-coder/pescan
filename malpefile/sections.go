package malpefile

func (p *PEFile) Section() {
	p.logger.Debug("start sections...")

	sections := make([]Section, 0, p.peFile.NtHeader.FileHeader.NumberOfSections)
	for _, elem := range p.peFile.Sections {
		p.Data.Info.CalculatedFileSize = int(elem.Header.VirtualAddress) + int(elem.Header.VirtualSize)
		section := Section{
			Name:             elem.NameString(),
			Rva:              Hex(uint64(elem.Header.VirtualAddress)),
			VirtualSize:      Hex(uint64(elem.Header.VirtualSize)),
			PointerToRawData: elem.Header.PointerToRawData,
			SizeOfRawData:    elem.Header.SizeOfRawData,
			Entropy:          elem.Entropy,
			MD5:              getMD5(elem.Data(0, 0, p.peFile)),
		}
		sections = append(sections, section)
	}
	p.Data.Sections = sections

	p.logger.Debugf("sections end: %+v", sections)
}
