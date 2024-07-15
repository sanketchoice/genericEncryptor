package genericEncryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
)

// PKCS5Padding adds padding to the plaintext for AES encryption
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS5Unpadding removes padding from the plaintext after AES decryption
func PKCS5Unpadding(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}

// ecbEncrypter implements cipher.BlockMode for ECB encryption
type ecbEncrypter struct {
	b cipher.Block
}

// NewECBEncrypter creates an ECB encrypter from the given block
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return &ecbEncrypter{b: b}
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

// AesEncrypt encrypts plaintext using AES ECB mode with PKCS5 padding
func AesEncrypt(plainText string, key string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	plaintext := []byte(plainText)
	plaintext = PKCS5Padding(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(plaintext))
	ecb := NewECBEncrypter(block)
	ecb.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}

// AesDecrypt decrypts ciphertext using AES ECB mode with PKCS5 padding
func AesDecrypt(ciphertext []byte, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	ecb := NewECBDecrypter(block)
	plaintext := make([]byte, len(ciphertext))
	ecb.CryptBlocks(plaintext, ciphertext)

	plaintext = PKCS5Unpadding(plaintext)

	return string(plaintext), nil
}

// ecbDecrypter implements cipher.BlockMode for ECB decryption
type ecbDecrypter struct {
	b         cipher.Block
	blockSize int
}

// NewECBDecrypter creates an ECB decrypter from the given block
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
