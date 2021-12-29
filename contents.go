package wadlib

import (
	"errors"
)

var (
	ErrInvalidIndex = errors.New("index does not exist within WAD")
)

// GetContent returns the data for the given index.
func (w *WAD) GetContent(index int) ([]byte, error) {
	// Ensure the index is valid.
	if index > len(w.Data) {
		return nil, ErrInvalidIndex
	}

	titleKey := w.Ticket.GetTitleKey()
	return w.Data[index].DecryptData(titleKey)
}

// UpdateContent updates the data at the given index with the given content.
func (w *WAD) UpdateContent(index int, contents []byte) error {
	// Ensure the index is valid.
	if index > len(w.Data) {
		return ErrInvalidIndex
	}

	titleKey := w.Ticket.GetTitleKey()
	w.Data[index].UpdateData(contents, titleKey)
	return nil
}

// ChangeTitleKey updates the ticket to contain the given title key,
// and re-encrypts all data to match.
func (w *WAD) ChangeTitleKey(updatedKey [16]byte) error {
	// Obtain the current title key.
	oldTitleKey := w.Ticket.GetTitleKey()

	// Save existing title data to a separate array.
	titleData := make(map[int][]byte)
	for index, data := range w.Data {
		decrypted, err := data.DecryptData(oldTitleKey)
		if err != nil {
			return err
		}

		titleData[index] = decrypted
	}

	// Update our title key.
	w.Ticket.UpdateTitleKey(updatedKey)

	// Encrypt our separate title data.
	for index, data := range titleData {
		w.Data[index].UpdateData(data, updatedKey)
	}

	return nil
}
