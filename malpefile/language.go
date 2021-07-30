package malpefile

import (
	"pescan/pe"
	"regexp"
	"strings"
)

func (p *PEFile) Language() {

}

func getImportFunctionEndsWithDll(peFile *pe.File) []string {
	funcNameList := make([]string, 0)
	for _, imp := range peFile.Imports {
		impLower := strings.ToLower(imp.Name)

		if strings.Contains(impLower, "dll") {
			funcNameList = append(funcNameList, imp.Name)
		}
	}
	return funcNameList
}

func checkModule(funcNameList []string, match string) bool {
	for _, funcName := range funcNameList {
		if strings.Contains(funcName, match) {
			return true
		}
	}
	return false
}

func GetStrings(content []byte) {
	reg := "[0-9A-_a-z\\-\\.:]{4,}"
	a, err := regexp.Compile(reg)
	if err != nil {

	}
	a.FindAll(content, 0)
	return
}
