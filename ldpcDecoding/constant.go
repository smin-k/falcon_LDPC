package ldpcDecoding

const (
	BigInfinity = 1000000.0
	Inf         = 64.0
	MaxNonce    = 1<<32 - 1

	// These parameters are only used for the decoding function.
	maxIter  = 20   // The maximum number of iteration in the decoder
	crossErr = 0.01 // A transisient error probability. This is also fixed as a small value
)

const (
	ModeNormal Mode = iota
	//ModeShared
	ModeTest
	ModeFake
	ModeFullFake
)
