package malpefile

import (
	"pescan/pe"
	"strings"
)

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
	for entryIndex, dataDirectory := range OptionalHeader.DataDirectory {
		if dataDirectory.Size != 0 || dataDirectory.VirtualAddress != 0 {
			customDataDirectory := &DataDirectory{
				VirtualAddress: Hex(uint64(dataDirectory.VirtualAddress)),
				Size:           dataDirectory.Size,
				Name:           getDataDirectoryName(entryIndex),
			}
			dataDirectoryList = append(dataDirectoryList, customDataDirectory)
		}
	}
	return dataDirectoryList
}

func getInfoDataDirectoryFromOptionalHeader64(OptionalHeader pe.ImageOptionalHeader64) []*DataDirectory {

	dataDirectoryList := make([]*DataDirectory, 0, len(OptionalHeader.DataDirectory))
	for entryIndex, dataDirectory := range OptionalHeader.DataDirectory {
		if dataDirectory.Size != 0 || dataDirectory.VirtualAddress != 0 {
			customDataDirectory := &DataDirectory{
				VirtualAddress: Hex(uint64(dataDirectory.VirtualAddress)),
				Size:           dataDirectory.Size,
				Name:           getDataDirectoryName(entryIndex),
			}
			dataDirectoryList = append(dataDirectoryList, customDataDirectory)
		}
	}
	return dataDirectoryList
}

func getDataDirectoryName(entryIndex int) string {
	name := pe.DataDirMap[entryIndex]
	return strings.ToUpper(name)
}
