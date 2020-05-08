package wadlib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/ioutil"
)

// WAD describes the structure enclosing information in a typical WAD's format.
type WAD struct {
	// BinaryContents is a structure representing
	Header                    BinaryWAD
	CertificateChain          []byte
	CertificateRevocationList []byte
	Ticket                    Ticket
	RawData                   []byte
	Meta                      []byte
}

type BinaryWAD struct {
	HeaderSize      uint32
	WADType         uint32
	CertificateSize uint32
	CRLSize         uint32
	TicketSize      uint32
	TMDSize         uint32
	DataSize        uint32
	MetaSize        uint32
}

// WADType contains a list of WAD types to compare against.
const (
	// Used for IOS, channels, and roughly all other items.
	WADTypeCommon = 0x49730000
	// Used for WADs containing boot-related items.
	WADTypeBoot = 0x69620000
	// Documented under https://wiibrew.org/wiki/WAD_files#Header by bushing.
	// I have not encountered this format in the wild, nor any SDK.
	WADTypeUnknown = 0x426b000
)

func getPadding(size uint32) uint32 {
	// You shouldn't pad nothing to begin with.
	if size == 0 {
		return 0
	}

	// We can calculate padding from the remainder.
	leftover := size % 64
	return 64 - leftover
}

// LoadWADFromFile takes a path, loads it, and parses the given binary WAD.
func LoadWADFromFile(filePath string) (*WAD, error) {
	contents, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return LoadWAD(contents)
}

// LoadWAD takes contents and parses the given binary WAD.
func LoadWAD(contents []byte) (*WAD, error) {
	var wad BinaryWAD

	loadingBuf := bytes.NewBuffer(contents[:32])
	err := binary.Read(loadingBuf, binary.BigEndian, &wad)
	if err != nil {
		return nil, err
	}

	// Simple sanity check.
	if int(wad.HeaderSize) != 32 {
		return nil, errors.New("header should be 32 bytes in default Nintendo configuration")
	}

	if int(wad.CertificateSize+wad.CRLSize+wad.TicketSize+wad.TMDSize+wad.DataSize+wad.MetaSize) > len(contents) {
		return nil, errors.New("contents as described in header were in sum larger than contents passed")
	}

	// To align with 0x40, we would now need to read 0x20 more bytes to get to the certificates/CRL data.
	// Thankfully, we have the entire array and can just avoid that.
	currentlyRead := wad.HeaderSize + getPadding(wad.HeaderSize)

	certificate := contents[currentlyRead : currentlyRead+wad.CertificateSize]
	currentlyRead += wad.CertificateSize + getPadding(wad.CertificateSize)

	crl := contents[currentlyRead : currentlyRead+wad.CRLSize]
	currentlyRead += wad.CRLSize + getPadding(wad.CRLSize)

	var ticket Ticket
	loadingBuf = bytes.NewBuffer(contents[currentlyRead : currentlyRead+wad.TicketSize])
	err = binary.Read(loadingBuf, binary.BigEndian, &ticket)
	if err != nil {
		return nil, err
	}

	currentlyRead += wad.TicketSize + getPadding(wad.TicketSize)

	var tmd TMD
	loadingBuf = bytes.NewBuffer(contents[currentlyRead : currentlyRead+wad.TMDSize])
	err = binary.Read(loadingBuf, binary.BigEndian, &wad)
	if err != nil {
		return nil, err
	}

	data := contents[currentlyRead : currentlyRead+wad.DataSize]
	currentlyRead += wad.DataSize + getPadding(wad.DataSize)

	meta := contents[currentlyRead : currentlyRead+wad.MetaSize]

	return &WAD{
		Header:                    wad,
		CertificateChain:          certificate,
		CertificateRevocationList: crl,
		Ticket:                    ticket,
		RawData:                   data,
		Meta:                      meta,
	}, nil
}
