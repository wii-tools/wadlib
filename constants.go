package wadlib

// SignatureType allows specification of the type of signature to be parsed in a ticket.
type SignatureType uint32

const (
	// SignatureRSA2048 is only one of several internal signature types.
	// See https://git.io/JfJzH or, from acer_cloud_wifi_copy,
	// /sw_x/es_core/esc/core/base/include/esitypes.h#L74
	// However, only RSA 2048 is used in the Wii's title system.
	SignatureRSA2048 SignatureType = 0x00010001
)

type WADType uint32

// WADType contains a list of WAD types to compare against.
const (
	// WADTypeCommon is used for IOS, channels, and roughly all other items.
	WADTypeCommon WADType = 0x49730000
	// WADTypeBoot is used for WADs containing boot-related items.
	WADTypeBoot = 0x69620000
	// WADTypeUnknown is documented under https://wiibrew.org/wiki/WAD_files#Header by bushing.
	// I have not encountered this format in the wild, nor any SDK.
	WADTypeUnknown = 0x426b000
)

// ESLicenseType describes the current title's license type.
type ESLicenseType uint8

const (
	LicensePermanent ESLicenseType = iota
	LicenseDemo
	LicenseTrial
	LicenseRental
	LicenseSubscription
	LicenseService
)

// ContentType specifies the type of content expected.
// It can be a shared content held in /shared2,
// or a normal content for the title itself.
type ContentType uint16

const (
	TitleTypeNormal ContentType = 0x0001
	TitleTypeShared             = 0x8001
)
