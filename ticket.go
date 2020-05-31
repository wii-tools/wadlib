package wadlib

// Ticket defines the binary structure of a given ticket file.
type Ticket struct {
	SignatureType SignatureType
	Signature     [256]byte
	// Signature padding to nearest 64 bytes
	_                [60]byte
	Issuer           [64]byte
	ECDHData         [60]byte
	FileVersion      uint8
	CACRLVersion     uint8
	SignerCRLVersion uint8
	TitleKey         [16]byte
	Padding          byte
	TicketID         uint64
	ConsoleID        uint32
	TitleID          uint64
	SystemAccessMask [2]uint8
	TitleVersion     uint16
	// WiiBrew describes this as the "Permitted Titles Mask".
	// estypes.h does not agree. We'll use the official description.
	AccessTitleID   uint32
	AccessTitleMask uint32
	LicenseType     uint8
	KeyType         uint8
	Unknown         [114]byte
	TimeLimits      [8]TimeLimitEntry
}

// TimeLimitEntry holds a time limit entry for a title.
type TimeLimitEntry struct {
	// It's unknown what code represents.
	Code uint32
	// Each limit is in seconds.
	Limit uint32
}
