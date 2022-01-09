package wadlib

import _ "embed"

var (
	// CertChainTemplate is an example certificate chain
	// that may go alongside a TMD.
	//go:embed templates/certs
	CertChainTemplate []byte

	// TMDTemplate is an example TMD that may be loaded
	// in order to create a custom WAD.
	//go:embed templates/tmd
	TMDTemplate []byte

	// TicketTemplate is an example Ticket that may be loaded
	// in order to create a custom WAD.
	//go:embed templates/tik
	TicketTemplate []byte
)
