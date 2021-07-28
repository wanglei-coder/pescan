package malpefile

import (
	"encoding/json"
	"fmt"
	"github.com/saferwall/pe"
	"strings"
)

func (p *PEFile) Resources() {

}

func getResources(peFile *pe.File) []*Resource {
	if peFile.Resources == nil {
		return nil
	}

	count := 1
	for _, resourceType := range peFile.Resources.Entries {
		for _, resourceId := range resourceType.Directory.Entries {
			for _, resourceLang := range resourceId.Directory.Entries {

				offset := resourceLang.Data.Struct.OffsetToData
				size := resourceLang.Data.Struct.Size
				data, err := getData(offset, size, peFile)
				fmt.Println(len(data), data[0], data[len(data)-1])
				if err != nil {
					continue
				}

				var resource Resource
				resource.Name = resourceType.Name
				resource.Entropy = getEntropy(data)
				resource.MD5 = getMD5(data)
				resource.SHA256 = getSHA256(data)
				resource.Type = getType(data)
				resource.Offset = Hex(uint64(offset))
				resource.Size = Hex(uint64(size))
				resource.Language = getLang(resourceLang)
				resource.SubLanguage = getSubLang(resourceLang)
				resource.Id = count
				resource.LanguageDesc = getLanguageDesc(resourceLang)

				count++
				d, _ := json.Marshal(resource)
				fmt.Println(string(d))
			}
		}
	}
	return nil
}

func getName(resourceType pe.ResourceDirectoryEntry) string {
	if resourceType.Name != "" {
		return resourceType.Name
	}

	name, found := ResourceType[resourceType.ID]
	if found {
		switch name.(type) {
		case string:
			return name.(string)
		}
	}
	return "UNKNOWN"
}

func getLang(resourceLang pe.ResourceDirectoryEntry) string {
	key := int(resourceLang.Data.Lang)
	if langName, found := LANG[key]; found {
		return langName.(string)
	}
	return ""
}

func getSubLang(resourceLang pe.ResourceDirectoryEntry) string {
	var langName string
	var subLangNames []string

	lang := int(resourceLang.Data.Lang)
	value, found := LANG[lang]
	if !found {
		langName = "*unknown*"
	} else {
		langName = value.(string)
	}

	subLang := int(resourceLang.Data.Sublang)

	value, found = SubLanguage[subLang]
	if !found {
		subLangNames = []string{}
	} else {
		subLangNames = value.([]string)
	}

	for _, subLangName := range subLangNames {
		if strings.Contains(subLangName, langName) {
			return subLangName
		}
	}

	if found {
		return subLangNames[0]
	}

	return "*unknown*"
}

func getLanguageDesc(resourceLang pe.ResourceDirectoryEntry) string {
	key := int(resourceLang.ID)
	if languageDesc, found := Lcid[key]; found {
		return languageDesc
	}
	return "unknown language"
}

func getSectionByRva(rva uint32, peFile *pe.File) *pe.Section {
	for _, section := range peFile.Sections {
		if section.Contains(rva, peFile) {
			return &section
		}
	}
	return nil
}

func getData(offset, size uint32, peFile *pe.File) ([]byte, error) {
	//totalSize := offset + size

	section := getSectionByRva(offset, peFile)
	if section != nil {
		return section.Data(offset, size, peFile), nil
	}

	buf, err := peFile.ReadBytesAtOffset(offset, size)
	return buf, err
}

func getSectionData(rva, length uint32, peFile *pe.File) []byte {
	return nil
}
