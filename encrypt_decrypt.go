package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"io/ioutil"
	"log"
)

func encryptFile(key []byte, inputFile, outputFile string) error {
	plaintext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	mode := cipher.NewCBCEncrypter(block, iv)

	// Pad plaintext to block size
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	for i := 0; i < pad; i++ {
		plaintext = append(plaintext, byte(pad))
	}

	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ioutil.WriteFile(outputFile, ciphertext, 0644)
}

func decryptFile(key []byte, inputFile, outputFile string) error {
	ciphertext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if len(ciphertext) < aes.BlockSize {
		return err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	pad := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-pad]

	return ioutil.WriteFile(outputFile, plaintext, 0644)
}

func main() {
	// 32 bytes key for AES-256
	key := []byte("this_is_32_bytes_long_secret_key!!")

	err := encryptFile(key, "secret.txt", "secret.enc")
	if err != nil {
		log.Fatal("Encryption error:", err)
	}

	err = decryptFile(key, "secret.enc", "decrypted.txt")
	if err != nil {
		log.Fatal("Decryption error:", err)
	}

	log.Println("Encryption and decryption complete.")
}
