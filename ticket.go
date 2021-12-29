package wadlib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io/ioutil"
)

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
	KeyType         KeyType
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

// selectCommonKey determines the proper key based on the index.
func (t *Ticket) selectCommonKey() [16]byte {
	switch t.KeyType {
	case KeyTypeCommon:
		return CommonKey
	case KeyTypeKoren:
		return KoreanKey
	case KeyTypevWii:
		return WiiUvWiiKey
	default:
		// Some WAD fakesigning utilities use an index outside of this list.
		// We assume the WAD is using the common key regardless.
		return CommonKey
	}
}

func (t *Ticket) GetTitleKey() [16]byte {
	// Use the appropriate common key per this ticket.
	key := t.selectCommonKey()

	// It should not be possible for our key not to be 16 bytes.
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}

	// The specified title ID is used as the IV.
	var titleId [16]byte
	binary.BigEndian.PutUint64(titleId[:], t.TitleID)

	// The resulting decrypted key is 16 bytes in length as well.
	blockMode := cipher.NewCBCDecrypter(block, titleId[:])
	decryptedKey := make([]byte, 16)

	// t.TitleKey is the current, encrypted contents from the original ticket.
	blockMode.CryptBlocks(decryptedKey, t.TitleKey[:])

	// Set this decrypted key to what we have stored.
	var titleKey [16]byte
	copy(titleKey[:], decryptedKey)
	return titleKey
}

// UpdateTitleKey updates the key for the given ticket.
// Note that this will not re-encrypt existing data for the WAD.
// Consider using WAD.ChangeTitleKey to re-encrypt instead, where possible.
func (t *Ticket) UpdateTitleKey(updated [16]byte) {
	// Use the appropriate common key per this ticket.
	key := t.selectCommonKey()

	// It should not be possible for our key not to be 16 bytes.
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}

	// The specified title ID is used as the IV.
	var titleId [16]byte
	binary.BigEndian.PutUint64(titleId[:], t.TitleID)

	// The resulting encrypted key is 16 bytes in length as well.
	blockMode := cipher.NewCBCEncrypter(block, titleId[:])
	encryptedKey := make([]byte, 16)

	// t.TitleKey is the current, encrypted contents from the original ticket.
	blockMode.CryptBlocks(encryptedKey, updated[:])

	// Set this encrypted key to what we have stored.
	var newTitleKey [16]byte
	copy(newTitleKey[:], encryptedKey)
	t.TitleKey = newTitleKey
}

// LoadTicket loads the given bytes from source into the Ticket for the current WAD.
func (w *WAD) LoadTicket(source []byte) error {
	var ticket Ticket
	loadingBuf := bytes.NewBuffer(source)
	err := binary.Read(loadingBuf, binary.BigEndian, &ticket)
	if err != nil {
		return err
	}

	w.Ticket = ticket
	return nil
}

// GetTicket returns the bytes of a given Ticket within the current WAD.
func (w *WAD) GetTicket() ([]byte, error) {
	ticket := w.Ticket

	var tmp bytes.Buffer
	err := binary.Write(&tmp, binary.BigEndian, ticket)
	if err != nil {
		return nil, err
	}

	contents, err := ioutil.ReadAll(&tmp)
	if err != nil {
		return nil, err
	}

	return contents, nil
}
