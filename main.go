package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	randomKey := make([]byte, 32)
	_, _ = rand.Read(randomKey)
	fmt.Printf("Key: \"%s\"\n", hex.EncodeToString(randomKey))

	block, err := aes.NewCipher(randomKey)
	if err != nil {
		fmt.Printf("Unable to create AES cipher. Cause: %s", err)
		panic(err)
	}

	secret := "Das ist ein Test"

	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	fmt.Printf("Nonce: \"%s\"\n", hex.EncodeToString(nonce))

	// Encrypt
	cipherText := aead.Seal(nil, nonce, []byte(secret), nil)

	encodedCipher := hex.EncodeToString(cipherText)

	fmt.Printf("Encrypted Text: \"%s\"\n", encodedCipher)

	// Decrypt
	plainText, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		fmt.Printf("Unable to decipher the cipher text. Cause: %s", err)
		panic(err)
	}
	fmt.Printf("Decrypted Text: \"%s\"\n", plainText)

	// Now we split the cipherText

	// Our part is the splittingSecret, we store it somewhere secure
	ourPart := make([]byte, len(cipherText))
	_, _ = rand.Read(ourPart)
	fmt.Printf("Our Part: \"%s\"\n", hex.EncodeToString(ourPart))

	// XOR the cipherText with the random splitting secret
	theirPart := make([]byte, len(cipherText))
	for i := range cipherText {
		theirPart[i] = ourPart[i] ^ cipherText[i]
	}
	fmt.Printf("Their Part: \"%s\"\n", hex.EncodeToString(theirPart))

	// Now we have two parts split apart with a true random byte slice

	// Reversing the operation

	// Consider adding checksums, length checks...
	mergedCipherText := make([]byte, len(theirPart))

	for i := range mergedCipherText {
		mergedCipherText[i] = theirPart[i] ^ ourPart[i]
	}
	fmt.Printf("Merged: \"%s\"\n", hex.EncodeToString(mergedCipherText))

	mergedPlainText, err := aead.Open(nil, nonce, mergedCipherText, nil)
	if err != nil {
		fmt.Printf("Unable to decipher the merged cipher text. Cause: %s", err)
		panic(err)
	}
	fmt.Printf("Decrypted Merged Text: \"%s\"\n", mergedPlainText)

}
