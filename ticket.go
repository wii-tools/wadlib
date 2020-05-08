package wadlib

// SignatureType allows specification of the type of signature to be parsed in a ticket.
const (
	// There's far more types than these internally!
	// See https://git.io/JfJzH or, from acer_cloud_wifi_copy,
	// /sw_x/es_core/esc/core/base/include/esitypes.h#L74
	// However, only RSA 2048 is used in the Wii's title system.
	SignatureTypeRSA2048 = 0x00010001
)

// ESLicenseType describes the current title's license type.
const (
	ESLicenseTypePermanent    = 0x0
	ESLicenseTypeDemo         = 0x1
	ESLicenseTypeTrial        = 0x2
	ESLicenseTypeRental       = 0x3
	ESLicenseTypeSubscription = 0x4
	ESLicenseTypeService      = 0x5
)

// TimeLimitEntry
type TimeLimitEntry struct {
	Code uint32
	// Each limit is in seconds.
	Limit uint32
}

// Ticket defines the binary structure of a given ticket file.
type Ticket struct {
	SignatureType    uint32
	Signature        [256]byte
	SignaturePadding [60]byte
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
	Unknown         [62]byte
	TimeLimits      [8]TimeLimitEntry
}
