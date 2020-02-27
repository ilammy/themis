package cell

/*
#cgo LDFLAGS: -lthemis -lsoter
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <themis/themis_error.h>
#include <themis/secure_cell.h>

#define MODE_SEAL 0
#define MODE_TOKEN_PROTECT 1
#define MODE_CONTEXT_IMPRINT 2

static bool get_protect_size(const void *key, size_t key_len, const void *data, size_t data_len, const void *context, size_t context_len, int mode, size_t *enc_len, size_t *add_len)
{
	themis_status_t res = THEMIS_FAIL;

	switch (mode)
	{
	case MODE_SEAL:
		res = themis_secure_cell_encrypt_seal(key, key_len, context, context_len, data, data_len, NULL, enc_len);
		break;
	case MODE_TOKEN_PROTECT:
		res = themis_secure_cell_encrypt_token_protect(key, key_len, context, context_len, data, data_len, NULL, add_len, NULL, enc_len);
		break;
	case MODE_CONTEXT_IMPRINT:
		if (!context)
		{
			break;
		}

		res = themis_secure_cell_encrypt_context_imprint(key, key_len, data, data_len, context, context_len, NULL, enc_len);
		break;
	}

	return THEMIS_BUFFER_TOO_SMALL == res;
}

static bool encrypt(const void *key, size_t key_len, const void *data, size_t data_len, const void *context, size_t context_len, int mode, void *enc, size_t enc_len, void *add, size_t add_len)
{
	themis_status_t res = THEMIS_FAIL;

	switch (mode)
	{
	case MODE_SEAL:
		res = themis_secure_cell_encrypt_seal(key, key_len, context, context_len, data, data_len, enc, &enc_len);
		break;
	case MODE_TOKEN_PROTECT:
		res = themis_secure_cell_encrypt_token_protect(key, key_len, context, context_len, data, data_len, add, &add_len, enc, &enc_len);
		break;
	case MODE_CONTEXT_IMPRINT:
		if (!context)
		{
			break;
		}

		res = themis_secure_cell_encrypt_context_imprint(key, key_len, data, data_len, context, context_len, enc, &enc_len);
		break;
	}

	return THEMIS_SUCCESS == res;
}

static bool get_unprotect_size(const void *key, size_t key_len, const void *prot, size_t prot_len, const void *add, size_t add_len, const void *context, size_t context_len, int mode, size_t *dec_len)
{
	themis_status_t res = THEMIS_FAIL;

	switch (mode)
	{
	case MODE_SEAL:
		res = themis_secure_cell_decrypt_seal(key, key_len, context, context_len, prot, prot_len, NULL, dec_len);
		break;
	case MODE_TOKEN_PROTECT:
		if (!add)
		{
			break;
		}

		res = themis_secure_cell_decrypt_token_protect(key, key_len, context, context_len, prot, prot_len, add, add_len, NULL, dec_len);
		break;
	case MODE_CONTEXT_IMPRINT:
		if (!context)
		{
			break;
		}

		res = themis_secure_cell_encrypt_context_imprint(key, key_len, prot, prot_len, context, context_len, NULL, dec_len);
		break;
	}

	return THEMIS_BUFFER_TOO_SMALL == res;
}

static bool decrypt(const void *key, size_t key_len, const void *prot, size_t prot_len, const void *add, size_t add_len, const void *context, size_t context_len, int mode, void *dec, size_t dec_len)
{
	themis_status_t res = THEMIS_FAIL;

	switch (mode)
	{
	case MODE_SEAL:
		res = themis_secure_cell_decrypt_seal(key, key_len, context, context_len, prot, prot_len, dec, &dec_len);
		break;
	case MODE_TOKEN_PROTECT:
		if (!add)
		{
			break;
		}

		res = themis_secure_cell_decrypt_token_protect(key, key_len, context, context_len, prot, prot_len, add, add_len, dec, &dec_len);
		break;
	case MODE_CONTEXT_IMPRINT:
		if (!context)
		{
			break;
		}

		res = themis_secure_cell_encrypt_context_imprint(key, key_len, prot, prot_len, context, context_len, dec, &dec_len);
		break;
	}

	return THEMIS_SUCCESS == res;
}

*/
import "C"
import (
	"github.com/cossacklabs/themis/gothemis/errors"
	"github.com/cossacklabs/themis/gothemis/utils"
)

// Secure Cell operation mode.
const (
	ModeSeal = iota
	ModeTokenProtect
	ModeContextImprint
)

// Secure Cell operation mode.
//
// Deprecated: Since 0.11. Use "cell.Mode..." constants instead.
const (
	CELL_MODE_SEAL            = ModeSeal
	CELL_MODE_TOKEN_PROTECT   = ModeTokenProtect
	CELL_MODE_CONTEXT_IMPRINT = ModeContextImprint
)

// SecureCell is a high-level cryptographic service aimed at protecting arbitrary data
// stored in various types of storage
type SecureCell struct {
	key  []byte
	mode int
}

// New makes a new Secure Cell with master key and specified mode.
func New(key []byte, mode int) *SecureCell {
	return &SecureCell{key, mode}
}

func missing(data []byte) bool {
	return data == nil || len(data) == 0
}

// Protect encrypts or signs data with optional user context (depending on the Cell mode).
func (sc *SecureCell) Protect(data []byte, context []byte) ([]byte, []byte, error) {
	if (sc.mode < ModeSeal) || (sc.mode > ModeContextImprint) {
		return nil, nil, errors.New("Invalid mode specified")
	}

	if missing(sc.key) {
		return nil, nil, errors.New("Master key was not provided")
	}
	safeKey := utils.WrapBuffer(sc.key)
	defer safeKey.Close()

	if missing(data) {
		return nil, nil, errors.New("Data was not provided")
	}
	safeData := utils.WrapBuffer(data)
	defer safeData.Close()

	if ModeContextImprint == sc.mode {
		if missing(context) {
			return nil, nil, errors.New("Context is mandatory for context imprint mode")
		}
	}
	safeContext := utils.WrapBuffer(context)
	defer safeContext.Close()

	var encLen, addLen C.size_t

	if !bool(C.get_protect_size(safeKey.Pointer(),
		C.size_t(safeKey.Length()),
		safeData.Pointer(),
		C.size_t(safeData.Length()),
		safeContext.Pointer(),
		C.size_t(safeContext.Length()),
		C.int(sc.mode),
		&encLen,
		&addLen)) {
		return nil, nil, errors.New("Failed to get output size")
	}

	encrypted := utils.WrapBuffer(make([]byte, encLen))
	defer encrypted.Close()
	var token []byte
	if addLen > 0 {
		token = make([]byte, addLen)
	}
	authToken := utils.WrapBuffer(token)
	defer authToken.Close()

	if !bool(C.encrypt(safeKey.Pointer(),
		C.size_t(safeKey.Length()),
		safeData.Pointer(),
		C.size_t(safeData.Length()),
		safeContext.Pointer(),
		C.size_t(safeContext.Length()),
		C.int(sc.mode),
		encrypted.Pointer(),
		C.size_t(encrypted.Length()),
		authToken.Pointer(),
		C.size_t(authToken.Length()))) {
		return nil, nil, errors.New("Failed to protect data")
	}

	return encrypted.Take(), authToken.Take(), nil
}

// Unprotect decrypts or verify data with optional user context (depending on the Cell mode).
func (sc *SecureCell) Unprotect(protectedData []byte, additionalData []byte, context []byte) ([]byte, error) {
	if (sc.mode < ModeSeal) || (sc.mode > ModeContextImprint) {
		return nil, errors.New("Invalid mode specified")
	}

	if missing(sc.key) {
		return nil, errors.New("Master key was not provided")
	}
	safeKey := utils.WrapBuffer(sc.key)
	defer safeKey.Close()

	if missing(protectedData) {
		return nil, errors.New("Data was not provided")
	}
	safeData := utils.WrapBuffer(protectedData)
	defer safeData.Close()

	if ModeContextImprint == sc.mode {
		if missing(context) {
			return nil, errors.New("Context is mandatory for context imprint mode")
		}
	}
	safeContext := utils.WrapBuffer(context)
	defer safeContext.Close()

	if ModeTokenProtect == sc.mode {
		if missing(additionalData) {
			return nil, errors.New("Additional data is mandatory for token protect mode")
		}
	}
	safeToken := utils.WrapBuffer(additionalData)
	defer safeToken.Close()

	var decLen C.size_t
	if !bool(C.get_unprotect_size(safeKey.Pointer(),
		C.size_t(safeKey.Length()),
		safeData.Pointer(),
		C.size_t(safeData.Length()),
		safeToken.Pointer(),
		C.size_t(safeToken.Length()),
		safeContext.Pointer(),
		C.size_t(safeContext.Length()),
		C.int(sc.mode),
		&decLen)) {
		return nil, errors.New("Failed to get output size")
	}

	decrypted := utils.WrapBuffer(make([]byte, decLen))
	defer decrypted.Close()

	if !bool(C.decrypt(safeKey.Pointer(),
		C.size_t(safeKey.Length()),
		safeData.Pointer(),
		C.size_t(safeData.Length()),
		safeToken.Pointer(),
		C.size_t(safeToken.Length()),
		safeContext.Pointer(),
		C.size_t(safeContext.Length()),
		C.int(sc.mode),
		decrypted.Pointer(),
		C.size_t(decrypted.Length()))) {
		return nil, errors.New("Failed to unprotect data")
	}

	return decrypted.Take(), nil
}
