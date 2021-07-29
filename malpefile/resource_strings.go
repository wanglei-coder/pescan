package malpefile

import "github.com/saferwall/pe"

const (
	BYTE  = 1
	WORD  = 2
	DWORD = 4

	DS_SETFONT = 0x40

	DIALOG_LEAD      = DWORD + DWORD + WORD + WORD + WORD + WORD + WORD
	DIALOG_ITEM_LEAD = DWORD + DWORD + WORD + WORD + WORD + WORD + WORD

	DIALOGEX_LEAD       = WORD + WORD + DWORD + DWORD + DWORD + WORD + WORD + WORD + WORD + WORD
	DIALOGEX_TRAIL      = WORD + WORD + BYTE + BYTE
	DIALOGEX_ITEM_LEAD  = DWORD + DWORD + DWORD + WORD + WORD + WORD + WORD + DWORD
	DIALOGEX_ITEM_TRAIL = WORD
)

var ITEM_TYPES = map[int]string{
	0x80: "BUTTON",
	0x81: "EDIT",
	0x82: "STATIC",
	0x83: "LIST BOX",
	0x84: "SCROLL BAR",
	0x85: "COMBO BOX",
}

func (p *PEFile) ResourceStrings() {

}

//func getResourceStrings(peFile *pe.File) {
//	if peFile.Resources == nil {
//		return
//	}
//
//	for _, dirType := range peFile.Resources.Entries {
//		dirTypeName := getDirTypeName(dirType)
//		for _, nameID := range dirType.Directory.Entries {
//			name := getNameIDName(nameID)
//			for _, language := range nameID.Directory.Entries {
//				var stringList []string
//
//				switch dirTypeName {
//				case "RT_DIALOG":
//					data_rva = language.Data.Struct.OffsetToData
//					size = language.Data.Struct.Size
//				case "RT_STRING":
//
//				}
//			}
//		}
//	}
//}

func getDirTypeName(dirType pe.ResourceDirectoryEntry) string {
	dirTypeName := dirType.Name
	if dirTypeName == "" {
		value, found := ResourceType[int(dirType.ID)]
		if found {
			return value.(string)
		}
	}
	return dirTypeName
}

func getNameIDName(nameID pe.ResourceDirectoryEntry) string {
	name := nameID.Name
	if name == "" {
		name = Hex(uint64(nameID.ID))
	}
	return name
}

//func
