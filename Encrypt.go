package genericEncryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ResponseBody struct {
	StatusCode int
	Message    string
	Body       map[string]string
}

func BadRequest(c *gin.Context, Message string) {
	response := ResponseBody{
		StatusCode: http.StatusBadRequest,
		Message:    Message,
	}
	c.AbortWithStatusJSON(http.StatusBadRequest, response)
}

func UnprocessableEntity(c *gin.Context, Message string) {
	response := ResponseBody{
		StatusCode: http.StatusUnprocessableEntity,
		Message:    Message,
	}
	c.AbortWithStatusJSON(http.StatusUnprocessableEntity, response)
}

// EncryptMapValues encrypts all values in a map using AES-256 encryption with the given key.
func EncryptMapValues(input map[string]interface{}, key []byte) (map[string]string, error) {
	result := make(map[string]string)

	for k, v := range input {
		plaintext := fmt.Sprintf("%v", v) // Convert value to string

		encryptedValue, err := EncryptAES(plaintext, key)
		if err != nil {
			return nil, err
		}

		result[k] = encryptedValue
	}

	return result, nil
}

// EncryptAES encrypts plainText using AES-256 encryption with the given key.
// func EncryptAES(plainText string, key []byte) (string, error) {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}

// 	plaintext := []byte(plainText)
// 	plaintext = PKCS5Padding(plaintext, block.BlockSize())

// 	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
// 	iv := ciphertext[:aes.BlockSize]
// 	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
// 		return "", err
// 	}

// 	mode := cipher.NewCBCEncrypter(block, iv)
// 	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

// 	return base64.StdEncoding.EncodeToString(ciphertext), nil
// }

func EncryptAES(plainText string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := []byte(plainText)
	plaintext = PKCS5Padding(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(plaintext))
	// ECB mode does not use IV
	mode := NewECBEncrypter(block)
	mode.CryptBlocks(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// NewECBEncrypter creates an ECB encrypter from the given block
func NewECBEncrypter(block cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{block}
}

type ecbEncrypter struct {
	block cipher.Block
}

func (x *ecbEncrypter) BlockSize() int {
	return x.block.BlockSize()
}

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	// Encrypt each block individually
	if len(src)%x.block.BlockSize() != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	for i := 0; i < len(src); i += x.block.BlockSize() {
		x.block.Encrypt(dst[i:i+x.block.BlockSize()], src[i:i+x.block.BlockSize()])
	}
}

// PKCS5Padding pads the plaintext to be a multiple of the block size.
func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padText...)
}
