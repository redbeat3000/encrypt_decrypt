package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func main() {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	fmt.Println("Your AES-256 Key (Base64):", base64.StdEncoding.EncodeToString(key))
}
