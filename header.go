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

func LoadHeader(source []byte) (WADHeader, error) {
	var header WADHeader
	loadingBuf := bytes.NewBuffer(source)
	err := binary.Read(loadingBuf, binary.BigEndian, &header)
	if err != nil {
		return WADHeader{}, err
	}
	return header, nil
}

func (w *WADHeader) GetHeader() []byte {
	var tmp bytes.Buffer
	err := binary.Write(&tmp, binary.BigEndian, w)
	if err != nil {
		panic(err)
	}

	contents, err := ioutil.ReadAll(&tmp)
	if err != nil {
		panic(err)
	}

	return contents
}