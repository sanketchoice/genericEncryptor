package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
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

// encryptMapValues encrypts all values in a map using AES-256 encryption with the given key.
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
func EncryptAES(plainText string, key []byte) (string, error) {
	// Create a new AES cipher block with the given key.
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Ensure the plaintext is a multiple of the block size
	plaintext := []byte(plainText)
	// It pads the plainText to ensure its length is a multiple of the AES block size using PKCS5Padding.
	plaintext = PKCS5Padding(plaintext, block.BlockSize())
	
	//It initializes a byte slice ciphertext to store the encrypted data.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	// It generates a random Initialization Vector (IV) of the AES block size length and prepends it to ciphertext.
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	//It creates a CBC (Cipher Block Chaining) encrypter mode using the AES block and the IV.
	mode := cipher.NewCBCEncrypter(block, iv)
	//It encrypts the padded plaintext using mode.CryptBlocks and stores the result in ciphertext.
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	//it encodes ciphertext in Base64 and returns it as a string, along with nil error if successful.
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// PKCS7Padding pads the plaintext to be a multiple of the block size.
func PKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padText...)
}
