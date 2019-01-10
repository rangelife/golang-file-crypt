package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	key := []byte(os.Args[2])
	plaintext, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	squishedtext := compress(plaintext)

	//	fmt.Printf("%s\n", plaintext)
	ciphertext, err := encrypt(key, squishedtext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%0x\n", ciphertext)

}

func compress(input []byte) []byte {
	var b bytes.Buffer
	gz, err := gzip.NewWriterLevel(&b, gzip.BestCompression)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := gz.Write(input); err != nil {
		log.Fatal(err)
	}
	if err := gz.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		log.Fatal(err)
	}
	return b.Bytes()
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}
