package wadlib

import "crypto/sha1"

var sha = sha1.New()

type WADFile struct {
	ContentRecord
	RawData []byte
}
