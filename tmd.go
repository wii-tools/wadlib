package wadlib

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
)

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

func LoadTMD(contents []byte) (TMD, error) {
	loadingBuf := bytes.NewBuffer(contents)

	// We have to read in the statically positioned values first.
	// The buffer will read in all it can,
	// which should be all values up to the variable contents at its end.
	var tmd BinaryTMD
	err := binary.Read(loadingBuf, binary.BigEndian, &tmd)
	if err != nil {
		return TMD{}, err
	}

	// Now, we create contents with the number of values as previously loaded.
	// The primary length of the TMD struct is 484 bytes.
	contentIndex := make([]ContentRecord, tmd.NumberOfContents)

	// We can now read to the end of the TMD to our contents.
	err = binary.Read(loadingBuf, binary.BigEndian, &contentIndex)
	if err != nil {
		return TMD{}, err
	}

	return TMD{
		tmd,
		contentIndex,
	}, nil
}

func (t *TMD) GetTMD() []byte {
	// First, handle the fixed-length BinaryTMD.
	var tmp bytes.Buffer
	err := binary.Write(&tmp, binary.BigEndian, t.BinaryTMD)
	if err != nil {
		panic(err)
	}

	// Then, write all individual content records.
	for _, content := range t.Contents {
		err := binary.Write(&tmp, binary.BigEndian, content)
		if err != nil {
			panic(err)
		}
	}

	// Read the buffer's contents.
	contents, err := ioutil.ReadAll(&tmp)
	if err != nil {
		panic(err)
	}

	return contents
}