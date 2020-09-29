package wadlib

import (
	"bytes"
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
	Data                      []WADFile
	Meta                      []byte
}

// getPadding returns the given size, padded to the nearest 0x40/64-byte boundary.
// This is useful as many types of contents are padded to such.
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

func pad(src []byte) []byte {
	length := (uint32)(len(src))
	paddedSize := getPadding(length)
	resized := make([]byte, paddedSize+length)
	copy(resized, src)
	return resized
}

// You use readable when you want to stagger contents and not use scary splice related methods.
type readable struct {
	data       []byte
	amountRead uint32
}

// getRange returns a range of data for a size. By default, it is padded to the closest 64 bytes.
func (r *readable) getRange(size uint32) []byte {
	current := r.amountRead
	// We'll want to return the range with actual data by size.
	selectedRange := r.data[current : current+size]
	// Then, we'll want to increment amountRead by the padded size.
	r.amountRead += size + getPadding(size)

	return selectedRange
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
	// The first u32 should be from the header, describing its own size.
	// It's important to check the exact order of these bytes to determine endianness.
	if !bytes.Equal(contents[0:4], []byte{0x00, 0x00, 0x00, 0x20}) {
		return nil, errors.New("header should be 32 bytes in default Nintendo configuration")
	}

	r := readable{
		data: contents,
	}
	wad := WAD{}

	// We'll read the header first as this is in order of the file.
	// We determined above that the header is 0x20 in length.
	err := wad.LoadHeader(r.getRange(0x20))
	if err != nil {
		return nil, err
	}

	// Simple sanity check.
	header := wad.Header
	if int(header.CertificateSize+header.CRLSize+header.TicketSize+header.TMDSize+header.DataSize+header.MetaSize) > len(contents) {
		return nil, errors.New("contents as described in header were in sum larger than contents passed")
	}

	// Next, the certificate section and CRL following.
	// As observed on the Wii, the CRL section is always 0,
	// along with any references to its version.
	wad.CertificateChain = r.getRange(header.CertificateSize)
	wad.CertificateRevocationList = r.getRange(header.CRLSize)

	// We'll next load a ticket from our contents into the struct.
	err = wad.LoadTicket(r.getRange(header.TicketSize))
	if err != nil {
		return nil, err
	}

	// Load the TMD following from our contents into the struct.
	// It needs a separate function to handle dynamic contents listed.
	err = wad.LoadTMD(r.getRange(header.TMDSize))
	if err != nil {
		return nil, err
	}

	// For each content, we want to separate the raw data.
	err = wad.LoadData(r.getRange(header.DataSize))
	if err != nil {
		return nil, err
	}

	// We're at the very end and can safely read to the very end of meta, ignoring subsequent data.
	wad.Meta = r.getRange(header.MetaSize)

	return &wad, nil
}

func (w *WAD) GetWAD(wadType WADType) ([]byte, error) {
	tmd, err := w.GetTMD()
	if err != nil {
		return nil, err
	}

	ticket, err := w.GetTicket()
	if err != nil {
		return nil, err
	}

	data := w.GetData()

	// Create a header with our sourced content.
	header := WADHeader{
		// This size is fixed, and matches Nintendo's size.
		HeaderSize:      0x20,
		WADType:         wadType,
		CertificateSize: (uint32)(len(w.CertificateChain)),
		CRLSize:         (uint32)(len(w.CertificateRevocationList)),
		TicketSize:      (uint32)(len(ticket)),
		TMDSize:         (uint32)(len(tmd)),
		DataSize:        (uint32)(len(data)),
		MetaSize:        (uint32)(len(w.Meta)),
	}
	w.Header = header

	headerContents, err := w.GetHeader()
	if err != nil {
		return nil, err
	}

	var final []byte
	final = append(final, pad(headerContents)...)
	final = append(final, pad(w.CertificateChain)...)
	final = append(final, pad(w.CertificateRevocationList)...)
	final = append(final, pad(ticket)...)
	final = append(final, pad(tmd)...)
	final = append(final, pad(data)...)
	final = append(final, pad(w.Meta)...)
	return final, nil
}
