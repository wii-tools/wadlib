package wadlib

import (
	"bytes"
	"encoding/binary"
	"io/ioutil"
)

// WADHeader describes a Nintendo WAD's typical header with sizes.
type WADHeader struct {
	HeaderSize      uint32
	WADType         WADType
	CertificateSize uint32
	CRLSize         uint32
	TicketSize      uint32
	TMDSize         uint32
	DataSize        uint32
	MetaSize        uint32
}

// LoadHeader creates a WADHeader based off of the given contents.
func (w *WAD) LoadHeader(source []byte) error {
	var header WADHeader
	loadingBuf := bytes.NewBuffer(source)
	err := binary.Read(loadingBuf, binary.BigEndian, &header)
	if err != nil {
		return err
	}
	w.Header = header
	return nil
}

// GetHeader returns bytes based off the WADHeader for the given WAD.
func (w *WAD) GetHeader() ([]byte, error) {
	var tmp bytes.Buffer
	err := binary.Write(&tmp, binary.BigEndian, w.Header)
	if err != nil {
		panic(err)
	}

	contents, err := ioutil.ReadAll(&tmp)
	if err != nil {
		return nil, err
	}

	return contents, nil
}
