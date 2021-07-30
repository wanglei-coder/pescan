package malpefile

import (
	"pescan/pe"
	"strings"
)

func (p *PEFile) Resources() {
	p.Data.Resources = getResources(p.peFile)
}

func getResources(peFile *pe.File) []*Resource {
	if peFile.Resources == nil {
		return nil
	}

	resourceList := make([]*Resource, 0, getResourceCount(peFile))
	count := 1
	for _, resourceType := range peFile.Resources.Entries {
		name := getName(resourceType)
		for _, resourceId := range resourceType.Directory.Entries {
			for _, resourceLang := range resourceId.Directory.Entries {

				offset := resourceLang.Data.Struct.OffsetToData
				size := resourceLang.Data.Struct.Size
				data, err := peFile.GetData(offset, size)
				if err != nil {
					continue
				}

				var resource Resource
				resource.Name = name
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

				resourceList = append(resourceList, &resource)
				count++
			}
		}
	}
	return resourceList
}

func getResourceCount(peFile *pe.File) int {
	count := 0
	for _, resourceType := range peFile.Resources.Entries {
		for _, resourceId := range resourceType.Directory.Entries {
			for range resourceId.Directory.Entries {
				count++
			}
		}
	}
	return count
}

func getName(resourceType pe.ResourceDirectoryEntry) string {
	if resourceType.Name != "" {
		return resourceType.Name
	}
	name, found := ResourceType[int(resourceType.ID)]
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
		switch langName.(type) {
		case string:
			return langName.(string)
		}
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
