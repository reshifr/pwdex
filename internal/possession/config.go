package possession

// type keyringSealedKey struct {
// 	Nonce      []byte `msgpack:"nonce"`
// 	Ciphertext []byte `msgpack:"ciphertext"`
// }

// type passwordSealedKey struct {
// 	Salt       []byte `msgpack:"salt"`
// 	Nonce      []byte `msgpack:"nonce"`
// 	Ciphertext []byte `msgpack:"ciphertext"`
// }

// type keyringSealedConfig struct {
// 	Salt      []byte           `msgpack:"salt"`
// 	SealedKey keyringSealedKey `msgpack:"sealed_key"`
// }

// type passwordSealedConfig struct {
// 	Salt      []byte            `msgpack:"salt"`
// 	SealedKey passwordSealedKey `msgpack:"sealed_key"`
// }

// type Config struct {
// 	Salt []byte
// 	Key  []byte
// }

// func seal(key []byte, nonce []byte, data []byte, aad []byte) ([]byte, error) {
// 	cipher, err := chacha20poly1305.NewX(key)
// 	if err != nil {
// 		return nil, ErrEncryptionFailed
// 	}
// 	return cipher.Seal(nil, nonce, data, aad), nil
// }

// func sealKeyWithKeyring(
// 	service string,
// 	user string,
// 	key []byte,
// 	aad []byte,
// ) (*keyringSealedKey, error) {
// 	kek := make([]byte, internal.KeySize)
// 	if _, err := rand.Read(kek); err != nil {
// 		return nil, ErrCSPRNGFailed
// 	}
// 	kekB64 := base64.StdEncoding.EncodeToString(kek)
// 	if err := keyring.Set(service, user, kekB64); err != nil {
// 		return nil, ErrKeyringSetFailed
// 	}
// 	nonce := make([]byte, chacha20poly1305.NonceSizeX)
// 	if _, err := rand.Read(nonce); err != nil {
// 		return nil, ErrCSPRNGFailed
// 	}
// 	ciphertext, err := seal(kek, nonce, key, aad)
// 	if err != nil {
// 		return nil, ErrCSPRNGFailed
// 	}
// 	return &keyringSealedKey{
// 		Nonce:      nonce,
// 		Ciphertext: ciphertext,
// 	}, nil
// }

// func sealKeyWithPassword(
// 	password string,
// 	key []byte,
// 	aad []byte,
// ) (*passwordSealedKey, error) {
// 	salt := make([]byte, internal.Argon2idSaltSize)
// 	if _, err := rand.Read(salt); err != nil {
// 		return nil, ErrCSPRNGFailed
// 	}
// 	kek := argon2.IDKey(
// 		[]byte(password),
// 		salt,
// 		internal.Argon2idTime,
// 		internal.Argon2idMemory,
// 		internal.Argon2idThreads,
// 		internal.KeySize,
// 	)
// 	nonce := make([]byte, chacha20poly1305.NonceSizeX)
// 	if _, err := rand.Read(nonce); err != nil {
// 		return nil, ErrCSPRNGFailed
// 	}
// 	ciphertext, err := seal(kek, nonce, key, append(aad, salt...))
// 	if err != nil {
// 		return nil, ErrCSPRNGFailed
// 	}
// 	return &passwordSealedKey{
// 		Salt:       salt,
// 		Nonce:      nonce,
// 		Ciphertext: ciphertext,
// 	}, nil
// }

// func makeSessionSealedConfig(
// 	filename string,
// 	service string,
// 	user string,
// 	salt []byte,
// 	key []byte,
// ) error {
// 	sessionSealedKey, err := sealKeyWithKeyring(service, user, key, salt)
// 	if err != nil {
// 		return err
// 	}
// 	session := keyringSealedConfig{Salt: salt, SealedKey: *sessionSealedKey}
// 	file, err := os.OpenFile(
// 		filename+internal.AppSessionFileExtension,
// 		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
// 		0644,
// 	)
// 	if err != nil {
// 		return ErrOpenFileFailed
// 	}
// 	defer file.Close()
// 	encoded, err := msgpack.Marshal(session)
// 	if err != nil {
// 		return ErrEncodeConfigFailed
// 	}
// 	if _, err = file.Write(encoded); err != nil {
// 		return ErrWriteFileFailed
// 	}
// 	return nil
// }

// func makeBackupSealedConfig(
// 	filename string,
// 	password string,
// 	salt []byte,
// 	key []byte,
// ) error {
// 	backupSealedKey, err := sealKeyWithPassword(password, key, salt)
// 	if err != nil {
// 		return err
// 	}
// 	backup := passwordSealedConfig{Salt: salt, SealedKey: *backupSealedKey}
// 	file, err := os.OpenFile(
// 		filename+internal.AppBackupFileExtension,
// 		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
// 		0644,
// 	)
// 	if err != nil {
// 		return ErrOpenFileFailed
// 	}
// 	defer file.Close()
// 	encoded, err := msgpack.Marshal(backup)
// 	if err != nil {
// 		return ErrEncodeConfigFailed
// 	}
// 	if _, err = file.Write(encoded); err != nil {
// 		return ErrWriteFileFailed
// 	}
// 	return nil
// }

// func MakeConfig(filename string, password string) (*Config, error) {
// 	salt := make([]byte, internal.Argon2idSaltSize)
// 	if _, err := rand.Read(salt); err != nil {
// 		return nil, ErrCSPRNGFailed
// 	}
// 	key := make([]byte, internal.KeySize)
// 	if _, err := rand.Read(key); err != nil {
// 		return nil, ErrCSPRNGFailed
// 	}
// 	if err := makeSessionSealedConfig(filename, internal.AppName, "renolph", salt, key); err != nil {
// 		return nil, err
// 	}
// 	if err := makeBackupSealedConfig(filename, password, salt, key); err != nil {
// 		return nil, err
// 	}
// 	return &Config{
// 		Salt: salt,
// 		Key:  key,
// 	}, nil
// }
