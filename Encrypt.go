package genericEncryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"

	log "github.com/sirupsen/logrus"
)

// AesEncrypt performs AES encryption on the input string using the provided key.
func AesEncrypt(src, key string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		log.Error("AesEncrypt Error: ", err)
		return nil, err
	}
	if src == "" {
		log.Info("AesEncrypt Src Empty")
		return nil, nil
	}
	ecb := NewECBEncrypter(block)
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	return crypted, nil
}

// PKCS5Padding pads the ciphertext to be a multiple of blockSize according to PKCS5 padding scheme.
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// GetEncryptedData encrypts each string in requestData using AES and returns a slice of base64-encoded encrypted strings.
func GetEncryptedData(requestData []string, secretKey string) ([]string, error) {
	decodedSecretKey, _ := base64.URLEncoding.DecodeString(secretKey)

	var encodedDataOutput []string
	for _, plainText := range requestData {
		crypted, err := AesEncrypt(plainText, string(decodedSecretKey))
		if err == nil {
			encodedData := base64.StdEncoding.EncodeToString(crypted)
			encodedDataOutput = append(encodedDataOutput, encodedData)
		}
	}

	return encodedDataOutput, nil
}

// ecbEncrypter implements the ECB mode encryption using the given cipher.Block.
type ecbEncrypter struct {
	b cipher.Block
}

// NewECBEncrypter creates a new ECB mode encrypter based on the provided block cipher.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{b: b}
}

// BlockSize returns the block size of the underlying block cipher.
func (x *ecbEncrypter) BlockSize() int {
	return x.b.BlockSize()
}

// CryptBlocks encrypts full blocks of plaintext into ciphertext using ECB mode.
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.b.BlockSize() != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.b.BlockSize()])
		src = src[x.b.BlockSize():]
		dst = dst[x.b.BlockSize():]
	}
}
