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
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		logrus.Error("AesEncrypt Error: ", err)
		return nil, err
	}
	if src == "" {
		logrus.Info("AesEncrypt Src Empty")
		return nil, nil
	}
	ecb := NewECBEncrypter(block)
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	return crypted, nil
}

// NewECBEncrypter creates a new ECB encrypter instance.
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

// PKCS5Padding adds PKCS5 padding to the input.
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// DataEncrypt encrypts a single string input using the specified key.
func DataEncrypt(input string, key string) string {
	encData, _ := GetEncryptedData([]string{input}, key)
	return encData[0]
}

// GetEncryptedData encrypts multiple strings using the specified key.
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
