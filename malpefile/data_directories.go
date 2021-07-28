package malpefile

import "github.com/saferwall/pe"

func (p *PEFile) DataDirectory() {
	if p.peFile.Is32 {
		OptionalHeader := p.peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader32)
		p.Data.DataDirectories = getInfoDataDirectoryFromOptionalHeader32(OptionalHeader)
	} else {
		OptionalHeader := p.peFile.NtHeader.OptionalHeader.(pe.ImageOptionalHeader64)
		p.Data.DataDirectories = getInfoDataDirectoryFromOptionalHeader64(OptionalHeader)
	}
}

func getInfoDataDirectoryFromOptionalHeader32(OptionalHeader pe.ImageOptionalHeader32) []*DataDirectory {

	dataDirectoryList := make([]*DataDirectory, 0, len(OptionalHeader.DataDirectory))
	for _, dataDirectory := range OptionalHeader.DataDirectory {
		if dataDirectory.Size != 0 || dataDirectory.VirtualAddress != 0 {
			dataDirectoryList = append(dataDirectoryList, &DataDirectory{
				VirtualAddress: Hex(uint64(dataDirectory.VirtualAddress)),
				Size:           dataDirectory.Size,
			})
		}
	}
	return dataDirectoryList
}

func getInfoDataDirectoryFromOptionalHeader64(OptionalHeader pe.ImageOptionalHeader64) []*DataDirectory {

	dataDirectoryList := make([]*DataDirectory, 0, len(OptionalHeader.DataDirectory))
	for _, dataDirectory := range OptionalHeader.DataDirectory {
		if dataDirectory.Size != 0 || dataDirectory.VirtualAddress != 0 {
			dataDirectoryList = append(dataDirectoryList, &DataDirectory{
				VirtualAddress: Hex(uint64(dataDirectory.VirtualAddress)),
				Size:           dataDirectory.Size,
			})
		}
	}
	return dataDirectoryList
}
