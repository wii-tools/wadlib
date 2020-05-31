package wadlib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io/ioutil"
)

// WAD describes the structure enclosing information in a typical WAD's format.
type WAD struct {
	Header                    WADHeader
	CertificateChain          []byte
	CertificateRevocationList []byte
	Ticket                    Ticket
	TMD                       TMD
	RawData                   []byte
	Meta                      []byte
}

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

type WADType uint32

// WADType contains a list of WAD types to compare against.
const (
	// Used for IOS, channels, and roughly all other items.
	WADTypeCommon WADType = 0x49730000
	// Used for WADs containing boot-related items.
	WADTypeBoot = 0x69620000
	// Documented under https://wiibrew.org/wiki/WAD_files#Header by bushing.
	// I have not encountered this format in the wild, nor any SDK.
	WADTypeUnknown = 0x426b000
)

func getPadding(size uint32) uint32 {
	// Empty things aren't padded.
	if size == 0 {
		return 0
	}

	// We can calculate padding from the remainder.
	leftover := size % 64
	if leftover == 0 {
		return 0
	} else {
		return 64 - leftover
	}
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
	// Read the given header. Per Nintendo's configuration, this should only be 32 bytes.
	var header WADHeader
	loadingBuf := bytes.NewBuffer(contents[:32])
	err := binary.Read(loadingBuf, binary.BigEndian, &header)
	if err != nil {
		return nil, err
	}

	// Simple sanity check.
	if int(header.HeaderSize) != 32 {
		return nil, errors.New("header should be 32 bytes in default Nintendo configuration")
	}

	if int(header.CertificateSize+header.CRLSize+header.TicketSize+header.TMDSize+header.DataSize+header.MetaSize) > len(contents) {
		return nil, errors.New("contents as described in header were in sum larger than contents passed")
	}

	// To align with 0x40, we would now need to read 0x20 more bytes to get to the certificates/CRL data.
	// Thankfully, we have the entire contents in an array and can just avoid that.
	currentlyRead := header.HeaderSize + getPadding(header.HeaderSize)

	certificate := contents[currentlyRead : currentlyRead+header.CertificateSize]
	currentlyRead += header.CertificateSize + getPadding(header.CertificateSize)

	crl := contents[currentlyRead : currentlyRead+header.CRLSize]
	currentlyRead += header.CRLSize + getPadding(header.CRLSize)

	// Load a ticket from our contents into the struct.
	var ticket Ticket
	loadingBuf = bytes.NewBuffer(contents[currentlyRead : currentlyRead+header.TicketSize])
	err = binary.Read(loadingBuf, binary.BigEndian, &ticket)
	if err != nil {
		return nil, err
	}
	currentlyRead += header.TicketSize + getPadding(header.TicketSize)

	// Load the TMD following from our contents into the struct.
	var tmd TMD
	loadingBuf = bytes.NewBuffer(contents[currentlyRead : currentlyRead+header.TMDSize])
	err = binary.Read(loadingBuf, binary.BigEndian, &tmd)
	if err != nil {
		return nil, err
	}

	data := contents[currentlyRead : currentlyRead+header.DataSize]
	currentlyRead += header.DataSize + getPadding(header.DataSize)

	// We're at the very end and can safely read to the very end of meta, ignoring subsequent data.
	meta := contents[currentlyRead : currentlyRead+header.MetaSize]

	return &WAD{
		Header:                    header,
		CertificateChain:          certificate,
		CertificateRevocationList: crl,
		Ticket:                    ticket,
		TMD:                       tmd,
		RawData:                   data,
		Meta:                      meta,
	}, nil
}
