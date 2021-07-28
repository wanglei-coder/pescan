package malpefile

var SubLanguage = map[interface{}]interface{}{
	"SUBLANG_NEUTRAL":                    0,
	"SUBLANG_DEFAULT":                    1,
	"SUBLANG_SYS_DEFAULT":                2,
	"SUBLANG_ARABIC_SAUDI_ARABIA":        1,
	"SUBLANG_ARABIC_IRAQ":                2,
	"SUBLANG_ARABIC_EGYPT":               3,
	"SUBLANG_ARABIC_LIBYA":               4,
	"SUBLANG_ARABIC_ALGERIA":             5,
	"SUBLANG_ARABIC_MOROCCO":             6,
	"SUBLANG_ARABIC_TUNISIA":             7,
	"SUBLANG_ARABIC_OMAN":                8,
	"SUBLANG_ARABIC_YEMEN":               9,
	"SUBLANG_ARABIC_SYRIA":               10,
	"SUBLANG_ARABIC_JORDAN":              11,
	"SUBLANG_ARABIC_LEBANON":             12,
	"SUBLANG_ARABIC_KUWAIT":              13,
	"SUBLANG_ARABIC_UAE":                 14,
	"SUBLANG_ARABIC_BAHRAIN":             15,
	"SUBLANG_ARABIC_QATAR":               16,
	"SUBLANG_AZERI_LATIN":                1,
	"SUBLANG_AZERI_CYRILLIC":             2,
	"SUBLANG_CHINESE_TRADITIONAL":        1,
	"SUBLANG_CHINESE_SIMPLIFIED":         2,
	"SUBLANG_CHINESE_HONGKONG":           3,
	"SUBLANG_CHINESE_SINGAPORE":          4,
	"SUBLANG_CHINESE_MACAU":              5,
	"SUBLANG_DUTCH":                      1,
	"SUBLANG_DUTCH_BELGIAN":              2,
	"SUBLANG_ENGLISH_US":                 1,
	"SUBLANG_ENGLISH_UK":                 2,
	"SUBLANG_ENGLISH_AUS":                3,
	"SUBLANG_ENGLISH_CAN":                4,
	"SUBLANG_ENGLISH_NZ":                 5,
	"SUBLANG_ENGLISH_EIRE":               6,
	"SUBLANG_ENGLISH_SOUTH_AFRICA":       7,
	"SUBLANG_ENGLISH_JAMAICA":            8,
	"SUBLANG_ENGLISH_CARIBBEAN":          9,
	"SUBLANG_ENGLISH_BELIZE":             10,
	"SUBLANG_ENGLISH_TRINIDAD":           11,
	"SUBLANG_ENGLISH_ZIMBABWE":           12,
	"SUBLANG_ENGLISH_PHILIPPINES":        13,
	"SUBLANG_FRENCH":                     1,
	"SUBLANG_FRENCH_BELGIAN":             2,
	"SUBLANG_FRENCH_CANADIAN":            3,
	"SUBLANG_FRENCH_SWISS":               4,
	"SUBLANG_FRENCH_LUXEMBOURG":          5,
	"SUBLANG_FRENCH_MONACO":              6,
	"SUBLANG_GERMAN":                     1,
	"SUBLANG_GERMAN_SWISS":               2,
	"SUBLANG_GERMAN_AUSTRIAN":            3,
	"SUBLANG_GERMAN_LUXEMBOURG":          4,
	"SUBLANG_GERMAN_LIECHTENSTEIN":       5,
	"SUBLANG_ITALIAN":                    1,
	"SUBLANG_ITALIAN_SWISS":              2,
	"SUBLANG_KASHMIRI_SASIA":             2,
	"SUBLANG_KASHMIRI_INDIA":             2,
	"SUBLANG_KOREAN":                     1,
	"SUBLANG_LITHUANIAN":                 1,
	"SUBLANG_MALAY_MALAYSIA":             1,
	"SUBLANG_MALAY_BRUNEI_DARUSSALAM":    2,
	"SUBLANG_NEPALI_INDIA":               2,
	"SUBLANG_NORWEGIAN_BOKMAL":           1,
	"SUBLANG_NORWEGIAN_NYNORSK":          2,
	"SUBLANG_PORTUGUESE":                 2,
	"SUBLANG_PORTUGUESE_BRAZILIAN":       1,
	"SUBLANG_SERBIAN_LATIN":              2,
	"SUBLANG_SERBIAN_CYRILLIC":           3,
	"SUBLANG_SPANISH":                    1,
	"SUBLANG_SPANISH_MEXICAN":            2,
	"SUBLANG_SPANISH_MODERN":             3,
	"SUBLANG_SPANISH_GUATEMALA":          4,
	"SUBLANG_SPANISH_COSTA_RICA":         5,
	"SUBLANG_SPANISH_PANAMA":             6,
	"SUBLANG_SPANISH_DOMINICAN_REPUBLIC": 7,
	"SUBLANG_SPANISH_VENEZUELA":          8,
	"SUBLANG_SPANISH_COLOMBIA":           9,
	"SUBLANG_SPANISH_PERU":               10,
	"SUBLANG_SPANISH_ARGENTINA":          11,
	"SUBLANG_SPANISH_ECUADOR":            12,
	"SUBLANG_SPANISH_CHILE":              13,
	"SUBLANG_SPANISH_URUGUAY":            14,
	"SUBLANG_SPANISH_PARAGUAY":           15,
	"SUBLANG_SPANISH_BOLIVIA":            16,
	"SUBLANG_SPANISH_EL_SALVADOR":        17,
	"SUBLANG_SPANISH_HONDURAS":           18,
	"SUBLANG_SPANISH_NICARAGUA":          19,
	"SUBLANG_SPANISH_PUERTO_RICO":        20,
	"SUBLANG_SWEDISH":                    1,
	"SUBLANG_SWEDISH_FINLAND":            2,
	"SUBLANG_URDU_PAKISTAN":              1,
	"SUBLANG_URDU_INDIA":                 2,
	"SUBLANG_UZBEK_LATIN":                1,
	"SUBLANG_UZBEK_CYRILLIC":             2,
	"SUBLANG_DUTCH_SURINAM":              3,
	"SUBLANG_ROMANIAN":                   1,
	"SUBLANG_ROMANIAN_MOLDAVIA":          2,
	"SUBLANG_RUSSIAN":                    1,
	"SUBLANG_RUSSIAN_MOLDAVIA":           2,
	"SUBLANG_CROATIAN":                   1,
	"SUBLANG_LITHUANIAN_CLASSIC":         2,
	"SUBLANG_GAELIC":                     1,
	"SUBLANG_GAELIC_SCOTTISH":            2,
	"SUBLANG_GAELIC_MANX":                3,


	0: []string{"SUBLANG_NEUTRAL"},
	1: []string{"SUBLANG_DEFAULT",
		"SUBLANG_ARABIC_SAUDI_ARABIA",
		"SUBLANG_AZERI_LATIN",
		"SUBLANG_CHINESE_TRADITIONAL",
		"SUBLANG_DUTCH",
		"SUBLANG_ENGLISH_US",
		"SUBLANG_FRENCH",
		"SUBLANG_GERMAN",
		"SUBLANG_ITALIAN",
		"SUBLANG_KOREAN",
		"SUBLANG_LITHUANIAN",
		"SUBLANG_MALAY_MALAYSIA",
		"SUBLANG_NORWEGIAN_BOKMAL",
		"SUBLANG_PORTUGUESE_BRAZILIAN",
		"SUBLANG_SPANISH",
		"SUBLANG_SWEDISH",
		"SUBLANG_URDU_PAKISTAN",
		"SUBLANG_UZBEK_LATIN",
		"SUBLANG_ROMANIAN",
		"SUBLANG_RUSSIAN",
		"SUBLANG_CROATIAN",
		"SUBLANG_GAELIC"},
	2: []string{"SUBLANG_SYS_DEFAULT",
		"SUBLANG_ARABIC_IRAQ",
		"SUBLANG_AZERI_CYRILLIC",
		"SUBLANG_CHINESE_SIMPLIFIED",
		"SUBLANG_DUTCH_BELGIAN",
		"SUBLANG_ENGLISH_UK",
		"SUBLANG_FRENCH_BELGIAN",
		"SUBLANG_GERMAN_SWISS",
		"SUBLANG_ITALIAN_SWISS",
		"SUBLANG_KASHMIRI_SASIA",
		"SUBLANG_KASHMIRI_INDIA",
		"SUBLANG_MALAY_BRUNEI_DARUSSALAM",
		"SUBLANG_NEPALI_INDIA",
		"SUBLANG_NORWEGIAN_NYNORSK",
		"SUBLANG_PORTUGUESE",
		"SUBLANG_SERBIAN_LATIN",
		"SUBLANG_SPANISH_MEXICAN",
		"SUBLANG_SWEDISH_FINLAND",
		"SUBLANG_URDU_INDIA",
		"SUBLANG_UZBEK_CYRILLIC",
		"SUBLANG_ROMANIAN_MOLDAVIA",
		"SUBLANG_RUSSIAN_MOLDAVIA",
		"SUBLANG_LITHUANIAN_CLASSIC",
		"SUBLANG_GAELIC_SCOTTISH"},
	3: []string{"SUBLANG_ARABIC_EGYPT",
		"SUBLANG_CHINESE_HONGKONG",
		"SUBLANG_ENGLISH_AUS",
		"SUBLANG_FRENCH_CANADIAN",
		"SUBLANG_GERMAN_AUSTRIAN",
		"SUBLANG_SERBIAN_CYRILLIC",
		"SUBLANG_SPANISH_MODERN",
		"SUBLANG_DUTCH_SURINAM",
		"SUBLANG_GAELIC_MANX"},
	4: []string{"SUBLANG_ARABIC_LIBYA",
		"SUBLANG_CHINESE_SINGAPORE",
		"SUBLANG_ENGLISH_CAN",
		"SUBLANG_FRENCH_SWISS",
		"SUBLANG_GERMAN_LUXEMBOURG",
		"SUBLANG_SPANISH_GUATEMALA"},
	5: []string{"SUBLANG_ARABIC_ALGERIA",
		"SUBLANG_CHINESE_MACAU",
		"SUBLANG_ENGLISH_NZ",
		"SUBLANG_FRENCH_LUXEMBOURG",
		"SUBLANG_GERMAN_LIECHTENSTEIN",
		"SUBLANG_SPANISH_COSTA_RICA"},
	6: []string{"SUBLANG_ARABIC_MOROCCO",
		"SUBLANG_ENGLISH_EIRE",
		"SUBLANG_FRENCH_MONACO",
		"SUBLANG_SPANISH_PANAMA"},
	7: []string{"SUBLANG_ARABIC_TUNISIA",
		"SUBLANG_ENGLISH_SOUTH_AFRICA",
		"SUBLANG_SPANISH_DOMINICAN_REPUBLIC"},
	8: []string{"SUBLANG_ARABIC_OMAN",
		"SUBLANG_ENGLISH_JAMAICA",
		"SUBLANG_SPANISH_VENEZUELA"},
	9: []string{"SUBLANG_ARABIC_YEMEN",
		"SUBLANG_ENGLISH_CARIBBEAN",
		"SUBLANG_SPANISH_COLOMBIA"},
	10: []string{"SUBLANG_ARABIC_SYRIA",
		"SUBLANG_ENGLISH_BELIZE",
		"SUBLANG_SPANISH_PERU"},
	11: []string{"SUBLANG_ARABIC_JORDAN",
		"SUBLANG_ENGLISH_TRINIDAD",
		"SUBLANG_SPANISH_ARGENTINA"},
	12: []string{"SUBLANG_ARABIC_LEBANON",
		"SUBLANG_ENGLISH_ZIMBABWE",
		"SUBLANG_SPANISH_ECUADOR"},
	13: []string{"SUBLANG_ARABIC_KUWAIT",
		"SUBLANG_ENGLISH_PHILIPPINES",
		"SUBLANG_SPANISH_CHILE"},
	14: []string{"SUBLANG_ARABIC_UAE", "SUBLANG_SPANISH_URUGUAY"},
	15: []string{"SUBLANG_ARABIC_BAHRAIN", "SUBLANG_SPANISH_PARAGUAY"},
	16: []string{"SUBLANG_ARABIC_QATAR", "SUBLANG_SPANISH_BOLIVIA"},
	17: []string{"SUBLANG_SPANISH_EL_SALVADOR"},
	18: []string{"SUBLANG_SPANISH_HONDURAS"},
	19: []string{"SUBLANG_SPANISH_NICARAGUA"},
	20: []string{"SUBLANG_SPANISH_PUERTO_RICO"}}