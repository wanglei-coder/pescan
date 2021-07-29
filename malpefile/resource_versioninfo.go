package malpefile

import (
	"errors"
	"github.com/gonutz/w32/v2"
)

func (p *PEFile) ResourceVersionInfo() {

	p.Data.ResourceVersionInfo, _ = getResourceVersionInfo(p.Filename)

}

func getResourceVersionInfo(path string) (*ResourceVersionInfo, error) {
	size := w32.GetFileVersionInfoSize(path)
	if size < 0 {
		return nil, errors.New("GetFileVersionInfoSize failed")
	}

	info := make([]byte, size)
	if ok := w32.GetFileVersionInfo(path, info); !ok {
		return nil, errors.New("GetFileVersionInfo failed")
	}

	translations, ok := w32.VerQueryValueTranslations(info)
	if !ok || len(translations) == 0 {
		return nil, errors.New("no translation found")
	}
	translation := translations[0]

	resourceVersionInfo := &ResourceVersionInfo{
		CompanyName:      getItem(info, translation, w32.CompanyName),
		FileDescription:  getItem(info, translation, w32.FileDescription),
		FileVersion:      getItem(info, translation, w32.FileVersion),
		LegalCopyright:   getItem(info, translation, w32.LegalCopyright),
		LegalTrademarks:  getItem(info, translation, w32.LegalTrademarks),
		OriginalFilename: getItem(info, translation, w32.OriginalFilename),
		ProductVersion:   getItem(info, translation, w32.ProductVersion),
		PrivateBuild:     getItem(info, translation, w32.PrivateBuild),
		SpecialBuild:     getItem(info, translation, w32.SpecialBuild),
	}

	return resourceVersionInfo, nil
}

func getItem(block []byte, translation, item string) string {
	if value, found := w32.VerQueryValueString(block, translation, item); found {
		return value
	}
	return ""
}
