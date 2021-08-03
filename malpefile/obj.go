package malpefile

type Result struct {
	RichHeaderInfo  []*RichHeaderInfo `json:"rich_header_info,omitempty"`
	DataDirectories []*DataDirectory  `json:"data_directories,omitempty"`
	Info            Info              `json:"info"`
	Debug           Debug             `json:"debug"`
	Imports         Import            `json:"imports,omitempty"`
	//Imports             []map[string][]Function `json:"imports,omitempty"`
	ImpHash             string               `json:"imp_hash,omitempty"`
	Sections            []Section            `json:"sections,omitempty"`
	IsPacked            bool                 `json:"is_packed"`
	Exports             []*Export            `json:"exports,omitempty"`
	ExportsTimestamp    string               `json:"exports_timestamp,omitempty"`
	ExportsModuleName   string               `json:"exports_module_name,omitempty"`
	ResourceVersionInfo *ResourceVersionInfo `json:"resource_version_info,omitempty"`
	Resources           []*Resource          `json:"resources,omitempty"`
	Signature           Signature            `json:"signature"`
}

type Info struct {
	LinkerVersion      string      `json:"linker_version,omitempty"`
	ImageBase          int         `json:"image_base,omitempty"`
	CompileTime        CompileTime `json:"compiletime"`
	NumberOfSections   uint16      `json:"number_of_sections,omitempty"`
	OsVersion          string      `json:"os_version,omitempty"`
	SizeOfImage        uint32      `json:"size_of_image,omitempty"`
	EntryPoint         string      `json:"entry_point"`
	OriginalFilename   string      `json:"original_filename,omitempty"`
	FileDescription    string      `json:"file_description,omitempty"`
	MachineType        string      `json:"machine_type,omitempty"`
	CalculatedFileSize int         `json:"calculated_file_size,omitempty"`
}

type CompileTime struct {
	Unix     uint32 `json:"unix,omitempty"`
	DateTime string `json:"date_time,omitempty"`
}

type DataDirectory struct {
	Name           string `json:"name,omitempty"`
	VirtualAddress string `json:"virtual_address,omitempty"`
	Size           uint32 `json:"size,omitempty"`
}

type RichHeaderInfo struct {
	ToolID    uint16 `json:"tool_id,omitempty"`
	Version   uint16 `json:"version,omitempty"`
	TimesUsed uint32 `json:"times_used,omitempty"`
}

type Debug struct {
	TimeDateStamp uint32
}

type Import []map[string][]Function

//type Import struct {
//	Import map[string][]map[string]string
//}

type Function struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
}

type Section struct {
	Name             string  `json:"name,omitempty"`
	Rva              string  `json:"rva,omitempty"`
	VirtualSize      string  `json:"virtual_size,omitempty"`
	PointerToRawData uint32  `json:"pointer_to_raw_data,omitempty"`
	SizeOfRawData    uint32  `json:"raw_data_size,omitempty"`
	Entropy          float64 `json:"entropy,omitempty"`
	MD5              string  `json:"md5,omitempty"`
}

type Export struct {
	Ordinal uint32 `json:"ordinal,omitempty"`
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
}

type Resource struct {
	SubLanguage  string  `json:"sublanguage,omitempty"`
	Entropy      float64 `json:"entropy,omitempty"`
	Offset       string  `json:"offset,omitempty"`
	Id           int     `json:"id,omitempty"`
	Size         string  `json:"size,omitempty"`
	LanguageDesc string  `json:"language_desc,omitempty"`
	Name         string  `json:"name,omitempty"`
	Language     string  `json:"language,omitempty"`
	SHA256       string  `json:"sha256,omitempty"`
	Type         string  `json:"type,omitempty"`
	MD5          string  `json:"md5,omitempty"`
}

type Signature struct {
	Heuristic string  `json:"heuristic,omitempty"`
	Certs     []*Cert `json:"certs,omitempty"`
}

type Cert struct {
	Signers []*Signer `json:"signer,omitempty"`
	Others  []*Signer `json:"other,omitempty"`
}

type Signer struct {
	CertValidTo   string `json:"cert_valid_to"`
	CertSerialNo  string `json:"cert_serial_no"`
	CertValidFrom string `json:"cert_valid_from"`
	CertVersion   int    `json:"cert_version"`
	CertSubject   string `json:"cert_subject"`
	CertIssuer    string `json:"cert_issuer"`
}

type ResourceVersionInfo struct {
	CompanyName      string `json:"company_name,omitempty"`
	FileDescription  string `json:"file_description,omitempty"`
	FileVersion      string `json:"file_version,omitempty"`
	LegalCopyright   string `json:"legal_copyright,omitempty"`
	LegalTrademarks  string `json:"legal_trademarks,omitempty"`
	OriginalFilename string `json:"original_filename,omitempty"`
	ProductVersion   string `json:"product_version,omitempty"`
	PrivateBuild     string `json:"private_build,omitempty"`
	SpecialBuild     string `json:"special_build,omitempty"`
}
