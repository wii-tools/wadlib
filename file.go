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

func LoadData(data []byte, contents []ContentRecord, titleKey [16]byte) ([]WADFile, error) {
	// Each content within the data section is aligned to a 0x40/64-byte boundary.
	r := readable{
		data: data,
	}

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

		// The title's decrypted key will be what we'll decrypt with.
		block, err := aes.NewCipher(titleKey[:])
		if err != nil {
			return nil, err
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
		decryptedData := make([]byte, paddedSize)

		// ...and we're off!
		blockMode.CryptBlocks(decryptedData, encryptedData)

		// Trim off the excess padding once decrypted.
		decryptedData = decryptedData[:content.Size]

		// Ensure that the decrypted data matches the SHA-1 hash given in the contents list.
		sha := sha1.Sum(decryptedData)
		if bytes.Compare(sha[:], content.Hash[:]) != 0 {
				return nil, errors.New(fmt.Sprintf("content %08x did not match the noted hash when decrypted", content.ID))
		}

		// We're all set!
		wads[content.Index] = WADFile{
			content,
			decryptedData,
		}
	}

	return wads, nil
}