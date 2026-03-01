package possession

import "errors"

var (
	ErrCSPRNGFailed       = errors.New("csprng failed")
	ErrEncryptionFailed   = errors.New("encryption failed")
	ErrKeyringGetFailed   = errors.New("failed to get secret in keyring")
	ErrKeyringSetFailed   = errors.New("failed to set secret in keyring")
	ErrEncodeConfigFailed = errors.New("failed to encode configuration")
	ErrDecodeConfigFailed = errors.New("failed to decode configuration")
	ErrOpenFileFailed     = errors.New("failed to open file")
	ErrWriteFileFailed    = errors.New("failed to write file")
)
