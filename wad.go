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

func sizeWithPadding(size uint32) uint32 {
	return size + getPadding(size)
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
	currentlyRead := sizeWithPadding(header.HeaderSize)

	certificate := contents[currentlyRead : currentlyRead+header.CertificateSize]
	currentlyRead += sizeWithPadding(header.CertificateSize)

	crl := contents[currentlyRead : currentlyRead+header.CRLSize]
	currentlyRead += sizeWithPadding(header.CRLSize)

	// Load a ticket from our contents into the struct.
	var ticket Ticket
	loadingBuf = bytes.NewBuffer(contents[currentlyRead : currentlyRead+header.TicketSize])
	err = binary.Read(loadingBuf, binary.BigEndian, &ticket)
	if err != nil {
		return nil, err
	}
	currentlyRead += sizeWithPadding(header.TicketSize)

	// Load the TMD following from our contents into the struct.
	// We have to read in the statically positioned values first.
	var tmd BinaryTMD
	tmdSize := uint32(binary.Size(tmd))
	loadingBuf = bytes.NewBuffer(contents[currentlyRead : currentlyRead+tmdSize])
	err = binary.Read(loadingBuf, binary.BigEndian, &tmd)
	if err != nil {
		return nil, err
	}
	// We've only partially read the full TMD, so only partially increment.
	currentlyRead += tmdSize

	// Now, we create contents with the number of values as previously loaded.
	// The primary length of the TMD struct is 484 bytes.
	contentIndex := make([]ContentRecord, tmd.NumberOfContents)
	// We can now read to the end of the TMD.
	remainingSize := header.TMDSize - tmdSize
	loadingBuf = bytes.NewBuffer(contents[currentlyRead : currentlyRead+remainingSize])
	err = binary.Read(loadingBuf, binary.BigEndian, &contentIndex)
	if err != nil {
		panic(err)
	}

	// We've now read the TMD in full.
	currentlyRead += remainingSize + getPadding(header.TicketSize)

	data := contents[currentlyRead : currentlyRead+header.DataSize]
	currentlyRead += sizeWithPadding(header.DataSize)

	// We're at the very end and can safely read to the very end of meta, ignoring subsequent data.
	meta := contents[currentlyRead : currentlyRead+header.MetaSize]

	return &WAD{
		Header:                    header,
		CertificateChain:          certificate,
		CertificateRevocationList: crl,
		Ticket:                    ticket,
		TMD: TMD{
			tmd,
			contentIndex,
		},
		RawData: data,
		Meta:    meta,
	}, nil
}
