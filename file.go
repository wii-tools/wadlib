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

type WADFile struct {
	ContentRecord
	RawData []byte
}

func (w *WAD) LoadData(data []byte) error {
	// Each content within the data section is aligned to a 0x40/64-byte boundary.
	r := readable{
		data: data,
	}
	titleKey := w.Ticket.TitleKey
	contents := w.TMD.Contents

	// TODO: We naively assume that the index will be accurately indexed from 0.
	// All observed Nintendo files follow this, but external tools may not follow this format.
	// We should most likely apply max index validation and sort,
	// otherwise data will read out of order in these cases.

	// All data contents will be the same amount as the number of contents per TMD.
	wads := make([]WADFile, len(contents))
	for _, content := range contents {
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
			ContentRecord: content,
			RawData:       encryptedData,
		}

		// Decrypt the loaded contents!
		err := file.DecryptData(titleKey)
		if err != nil {
			return err
		}

		wads[file.Index] = file
	}
	w.Data = wads

	return nil
}

func (w *WAD) GetData() []byte {
	var data []byte
	for _, content := range w.Data {
		// Data internally is aligned by 64 bytes.
		data = append(data, pad(content.RawData)...)
	}

	return data
}

func (d *WADFile) DecryptData(titleKey [16]byte) error {
	content := d.ContentRecord

	// The title's decrypted key will be what we'll decrypt with.
	block, err := aes.NewCipher(titleKey[:])
	if err != nil {
		return err
	}

	// The IV we'll use will be the two bytes sourced from the content's index,
	// padded with 14 null bytes.
	var indexBytes [2]byte
	binary.BigEndian.PutUint16(indexBytes[:], content.Index)

	iv := make([]byte, 16)
	iv[0] = indexBytes[0]
	iv[1] = indexBytes[1]

	blockMode := cipher.NewCBCDecrypter(block, iv)

	// The resulting decrypted contents is the same size as the input, including padding.
	decryptedData := make([]byte, len(d.RawData))

	// ...and we're off!
	blockMode.CryptBlocks(decryptedData, d.RawData)

	// Trim off the excess padding once decrypted.
	decryptedData = decryptedData[:content.Size]

	// Ensure that the decrypted data matches the SHA-1 hash given in the contents list.
	sha := sha1.Sum(decryptedData)
	if bytes.Compare(sha[:], content.Hash[:]) != 0 {
		return errors.New(fmt.Sprintf("content %08x did not match the noted hash when decrypted", content.ID))
	}

	// We're all set!
	d.RawData = decryptedData
	return nil
}

func (d *WADFile) EncryptData(titleKey [16]byte) error {
	content := d.ContentRecord

	// The title's decrypted key will be what we'll encrypt with.
	block, err := aes.NewCipher(titleKey[:])
	if err != nil {
		return err
	}

	// The IV we'll use will be the two bytes sourced from the content's index,
	// padded with 14 null bytes.
	var indexBytes [2]byte
	binary.BigEndian.PutUint16(indexBytes[:], content.Index)

	iv := make([]byte, 16)
	iv[0] = indexBytes[0]
	iv[1] = indexBytes[1]

	blockMode := cipher.NewCBCEncrypter(block, iv)

	// One must encrypt content to 16 bytes.
	// We pad with null bytes.
	paddedSize := uint32(content.Size)
	leftover := paddedSize % 16
	if leftover != 0 {
		paddedSize += 16 - leftover
	}

	decryptedData := make([]byte, paddedSize)
	copy(decryptedData, d.RawData)

	// The resulting encrypted contents is the same size as our adjusted input, including padding.
	encryptedData := make([]byte, len(decryptedData))

	// ...and we're off!
	blockMode.CryptBlocks(encryptedData, decryptedData)

	// Update the content record to reflect the hash of our origin content.
	sha := sha1.Sum(d.RawData)
	d.Hash = sha

	// We're all set!
	d.RawData = encryptedData
	return nil
}
