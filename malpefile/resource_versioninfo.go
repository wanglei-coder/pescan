package malpefile

import (
	"errors"
	"github.com/gonutz/w32/v2"
)

func (p *PEFile) ResourceVersionInfo() {
	defer func() {
		if err := recover(); err != nil {
			p.logger.Error("recover: ", err)
		}
	}()

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

	_getItem := func(item string) string {
		return getItem(info, translation, item)
	}

	resourceVersionInfo := &ResourceVersionInfo{
		CompanyName:      _getItem(w32.CompanyName),
		FileDescription:  _getItem(w32.FileDescription),
		FileVersion:      _getItem(w32.FileVersion),
		LegalCopyright:   _getItem(w32.LegalCopyright),
		LegalTrademarks:  _getItem(w32.LegalTrademarks),
		OriginalFilename: _getItem(w32.OriginalFilename),
		ProductVersion:   _getItem(w32.ProductVersion),
		PrivateBuild:     _getItem(w32.PrivateBuild),
		SpecialBuild:     _getItem(w32.SpecialBuild),
	}

	return resourceVersionInfo, nil
}

func getItem(block []byte, translation, item string) string {
	if value, found := w32.VerQueryValueString(block, translation, item); found {
		return value
	}
	return ""
}
