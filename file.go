package wadlib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

// WADFile represents a file within a WAD.
// RawData should always be the encrypted data ready to be stored within a WAD.
type WADFile struct {
	Record  *ContentRecord
	RawData []byte
}

// LoadDataSection loads the binary data from a WAD and parses it as specified within the TMD.
func (w *WAD) LoadDataSection(data []byte) error {
	// Each content within the data section is aligned to a 0x40/64-byte boundary.
	r := readable{
		data: data,
	}
	contents := w.TMD.Contents

	// TODO: We naively assume that the index will be accurately indexed from 0.
	// All observed Nintendo files follow this, but external tools may not follow this format.
	// We should most likely apply max index validation and sort,
	// otherwise data will read out of order in these cases.

	// All data contents will be the same amount as the number of contents per TMD.
	w.Data = make([]WADFile, len(contents))
	for idx, content := range w.TMD.Contents {
		// It's okay to cast this from a uint64 as the WAD file format
		// cannot exceed the maximum uint32 value within the data section.
		// We read aligned to 16 bytes as the encrypted data is stored with padding.
		// Not all contents meet the expected 16-byte boundary.
		paddedSize := uint32(content.Size)
		leftover := paddedSize % 16
		if leftover != 0 {
			paddedSize += 16 - leftover
		}

		// Read the padded amount as aligned to 64 bytes.
		encryptedData := r.getRange(paddedSize)

		file := WADFile{
			Record:  &w.TMD.Contents[idx],
			RawData: encryptedData,
		}

		w.Data[content.Index] = file
	}

	return nil
}

// GetDataSection returns data as specified within the TMD.
func (w *WAD) GetDataSection() []byte {
	var data []byte
	for _, content := range w.Data {
		// Data internally is aligned by 64 bytes.
		data = append(data, pad(content.RawData)...)
	}

	return data
}

// DecryptData returns the decrypted contents of this WADFile with the given title key.
func (d *WADFile) DecryptData(titleKey [16]byte) ([]byte, error) {
	// The passed title key will be what we'll decrypt with.
	// It must be 16 bytes.
	block, err := aes.NewCipher(titleKey[:])
	if err != nil {
		panic(err)
	}

	// The IV we'll use will be the two bytes sourced from the content's index,
	// padded with 14 null bytes.
	var indexBytes [2]byte
	binary.BigEndian.PutUint16(indexBytes[:], d.Record.Index)

	iv := make([]byte, 16)
	iv[0] = indexBytes[0]
	iv[1] = indexBytes[1]

	blockMode := cipher.NewCBCDecrypter(block, iv)

	// The resulting decrypted contents is the same size as the input, including padding.
	decryptedData := make([]byte, len(d.RawData))

	// ...and we're off!
	blockMode.CryptBlocks(decryptedData, d.RawData)

	// Trim off the excess padding once decrypted.
	decryptedData = decryptedData[:d.Record.Size]

	// Ensure that the decrypted data matches the SHA-1 hash given in the contents list.
	sha := sha1.Sum(decryptedData)
	if bytes.Compare(sha[:], d.Record.Hash[:]) != 0 {
		return nil, errors.New(fmt.Sprintf("content %08x did not match the noted hash when decrypted", d.Record.ID))
	}

	// We're all set!
	return decryptedData, nil
}

// UpdateData updates the contents of this WADFile with the given data and title key.
func (d *WADFile) UpdateData(contents []byte, titleKey [16]byte) {
	// The passed title key will be what we'll encrypt with.
	// It must be 16 bytes.
	block, err := aes.NewCipher(titleKey[:])
	if err != nil {
		panic(err)
	}

	// The IV we'll use will be the two bytes sourced from the content's index,
	// padded with 14 null bytes.
	var indexBytes [2]byte
	binary.BigEndian.PutUint16(indexBytes[:], d.Record.Index)

	iv := make([]byte, 16)
	iv[0] = indexBytes[0]
	iv[1] = indexBytes[1]

	blockMode := cipher.NewCBCEncrypter(block, iv)

	// Update the content record to reflect the hash and size of our new content.
	d.Record.Hash = sha1.Sum(contents)
	d.Record.Size = uint64(len(contents))

	// One must pad encrypted content to 16 bytes.
	// We pad with null bytes.
	paddedSize := d.Record.Size
	leftover := paddedSize % 16
	if leftover != 0 {
		paddedSize += 16 - leftover
	}

	decryptedData := make([]byte, paddedSize)
	copy(decryptedData, contents)

	// The resulting encrypted contents is the same size as our adjusted input, including padding.
	encryptedData := make([]byte, len(decryptedData))

	// ...and we're off!
	blockMode.CryptBlocks(encryptedData, decryptedData)
	d.RawData = encryptedData
}
