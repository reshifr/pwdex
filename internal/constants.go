package internal

const (
	AppName                 = "pwdex"
	AppVersion              = "1.0"
	AppSessionFileExtension = ".pwdex"
	AppBackupFileExtension  = ".bakpwdex"
	KeySize                 = 32

	// Uses the second recommended parameter set defined in RFC 9106 for Argon2id.
	// [RFC 9106 Parameter Choice]: https://www.rfc-editor.org/rfc/rfc9106.html#name-parameter-choice
	Argon2idSaltSize = 16        // 128-bit salt
	Argon2idTime     = 3         // 3 iterations
	Argon2idMemory   = 64 * 1024 // 64 MiB of RAM
	Argon2idThreads  = 4         // 4 lanes
)
