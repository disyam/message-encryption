package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"github.com/aead/ecdh"
)

func encrypt(secret []byte, plaintext []byte) (ciphertext []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(secret)
	if err != nil {
		return
	}
	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}
	ciphertext = aesgcm.Seal(nonce, nonce, plaintext, nil)
	return
}

func decrypt(secret []byte, encrypted []byte) (plaintext []byte, err error) {
	var block cipher.Block
	block, err = aes.NewCipher(secret)
	if err != nil {
		return
	}
	var aesgcm cipher.AEAD
	aesgcm, err = cipher.NewGCM(block)
	if err != nil {
		return
	}
	nonceSize := aesgcm.NonceSize()
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	return
}

func main() {
	keyExchange := ecdh.X25519()

	// create alice key
	alicePriv, alicePub, err := keyExchange.GenerateKey(nil)
	if err != nil {
		log.Fatalln(err)
	}

	// create bob key
	bobPriv, bobPub, err := keyExchange.GenerateKey(nil)
	if err != nil {
		log.Fatalln(err)
	}

	// create alice secret
	aliceSecret := keyExchange.ComputeSecret(alicePriv, bobPub)

	// create bob secret
	bobSecret := keyExchange.ComputeSecret(bobPriv, alicePub)

	// alice -> bob
	ciphertext1, err := encrypt(aliceSecret, []byte("Hello Bob!"))
	if err != nil {
		log.Fatalln(err)
	}
	message1, err := decrypt(bobSecret, ciphertext1)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("alice -> bob:", string(message1))

	// bob -> alice
	ciphertext2, err := encrypt(bobSecret, []byte("Hello Alice!"))
	if err != nil {
		log.Fatalln(err)
	}
	message2, err := decrypt(aliceSecret, ciphertext2)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println("bob -> alice:", string(message2))
}
