package wadlib

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
)

// BinaryTMD describes a byte-level format for a TMD.
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
	SystemVersionHigh uint32
	SystemVersionLow  uint32
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

// TMD describes a human-usable TMD format.
type TMD struct {
	BinaryTMD
	Contents []ContentRecord
}

// ContentRecord describes information about a given content.
type ContentRecord struct {
	ID    uint32
	Index uint16
	Type  ContentType
	Size  uint64
	Hash  [20]byte
}

// LoadTMD loads a given TMD from the passed contents into the WAD.
func (w *WAD) LoadTMD(contents []byte) error {
	loadingBuf := bytes.NewBuffer(contents)

	// We have to read in the statically positioned values first.
	// The buffer will read in all it can,
	// which should be all values up to the variable contents at its end.
	// The primary length of the TMD struct is 484 bytes.
	var tmd BinaryTMD
	err := binary.Read(loadingBuf, binary.BigEndian, &tmd)
	if err != nil {
		return err
	}

	// Now, we create contents with the number of values as previously loaded.
	contentIndex := make([]ContentRecord, tmd.NumberOfContents)

	// We can now read to the end of the TMD to our contents.
	err = binary.Read(loadingBuf, binary.BigEndian, &contentIndex)
	if err != nil {
		return err
	}

	w.TMD = TMD{
		tmd,
		contentIndex,
	}
	return nil
}

// GetTMD returns the bytes for the given TMD within the current WAD.
func (w *WAD) GetTMD() ([]byte, error) {
	// First, handle the fixed-length BinaryTMD.
	var tmp bytes.Buffer
	err := binary.Write(&tmp, binary.BigEndian, w.TMD.BinaryTMD)
	if err != nil {
		return nil, err
	}

	// Then, write all individual content records.
	for _, content := range w.TMD.Contents {
		err = binary.Write(&tmp, binary.BigEndian, content)
		if err != nil {
			return nil, err
		}
	}

	// Read the buffer's contents.
	contents, err := ioutil.ReadAll(&tmp)
	if err != nil {
		return nil, err
	}

	return contents, nil
}
