package genericEncryptor
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
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

// AesEncrypt encrypts the input using AES in ECB mode with PKCS5 padding.
func AesEncrypt(src, key string) ([]byte, error) {
	if len(key) == 0 {
		logrus.Info("AesEncrypt: Key is empty")
		return nil, nil // Returning nil, nil indicates no error occurred
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		logrus.Info("AesEncrypt: Error creating cipher block - ", err)
		return nil, err
	}
	if src == "" {
		logrus.Info("AesEncrypt: Source is empty")
		return nil, nil // Returning nil, nil indicates no error occurred
	}
	ecb := NewECBEncrypter(block)
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	return crypted, nil
}

func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{b: b}
}

type ecbEncrypter struct {
	b cipher.Block
}

func (x *ecbEncrypter) BlockSize() int {
	return x.b.BlockSize()
}

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.b.BlockSize() != 0 {
		logrus.Info("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		logrus.Info("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.b.BlockSize()])
		src = src[x.b.BlockSize():]
		dst = dst[x.b.BlockSize():]
	}
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func DataEncrypt(input string, key string) (string, error) {
	encData, err := GetEncryptedData([]string{input}, key)
	if err != nil {
		return "", err
	}
	return encData[0], nil
}

func GetEncryptedData(requestData []string, secretKey string) ([]string, error) {
	decodedSecretKey, err := base64.URLEncoding.DecodeString(secretKey)
	if err != nil {
		logrus.Info("GetEncryptedData: Error decoding secret key - ", err)
		return nil, err
	}

	var encodedDataOutput []string
	for _, plainText := range requestData {
		crypted, err := AesEncrypt(plainText, string(decodedSecretKey))
		if err != nil {
			logrus.Info("GetEncryptedData: Error encrypting data - ", err)
			continue // Skip current plaintext if encryption fails
		}
		encodedData := base64.StdEncoding.EncodeToString(crypted)
		encodedDataOutput = append(encodedDataOutput, encodedData)
	}
	return encodedDataOutput, nil
}
