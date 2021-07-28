package malpefile

type Result struct {
	RichHeaderInfo      []*RichHeaderInfo
	DataDirectories     []*DataDirectory
	Info                Info
	Debug               Debug
	Imports             []map[string][]Function
	ImpHash             string
	Sections            []Section
	Exports             []*Export
	ExportsTimestamp    string
	ExportsModuleName   string
	ResourceVersionInfo map[string]string
	Resources           []*Resource
}

type Info struct {
	CompileTime        CompileTime `json:"compile_time"`
	EntryPoint         string      `json:"entry_point"`
	OriginalFilename   string      `json:"original_filename,omitempty"`
	FileDescription    string      `json:"file_description,omitempty"`
	ImageBase          int         `json:"image_base,omitempty"`
	SizeOfImage        uint32      `json:"size_of_image,omitempty"`
	LinkerVersion      uint16      `json:"linker_version,omitempty"`
	OsVersion          uint32      `json:"os_version,omitempty"`
	NumberOfSections   uint16      `json:"number_of_sections,omitempty"`
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

type Import struct {
	Import map[string][]map[string]string
}

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