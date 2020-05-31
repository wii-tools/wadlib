package wadlib

type BinaryTMD struct {
	SignatureType SignatureType
	Signature     [256]byte
	// Signature padding to nearest 64 bytes
	_                 [60]byte
	Issuer            [64]byte
	FileVersion       uint8
	CACRLVersion      uint8
	SignerCRLVersion  uint8
	IsvWii            bool
	SystemVersion     uint64
	TitleID           uint64
	TitleType         uint32
	GroupID           uint16
	Unknown           uint16
	Region            uint16
	Ratings           [16]byte
	Reserved          [12]byte
	IPCMask           [12]byte
	Reserved2         [18]byte
	AccessRightsFlags uint32
	TitleVersion      uint16
	NumberOfContents  uint16
	BootIndex         uint16
	// Further alignment
	_ uint16
}

type TMD struct {
	BinaryTMD
	Contents []ContentRecord
}

type ContentRecord struct {
	ID    uint32
	Index uint16
	Type  ContentType
	Size  uint64
	Hash  [20]byte
}
