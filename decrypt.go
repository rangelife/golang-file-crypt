package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	key := []byte(os.Args[1])

	ciphertext := "33c9e4b04c81870a359a98bb1c5ea7691406a534c436901e29a78a0dfab8464f341d8b1ccf4f62db403d659a740a777d575c1a0f39f12fb2eab452392a9202584207543e60f7efa62e0c834b56adc8e067838f510076eefeb027e184d7ec76103f8462cb49eb00247620763731e88023518e24aeea94bee130cc70c3723b5c8016f8a2e3d8208cf8553cf76000a2a7a8f60aa3aa8c6990e9ba8b7e0b22ed1e8a9d6ceb473b0c50707665f631aa8efb58961f3398491deb88c79eacacc258eb45dd748577d435cd280ad1c5555e91ebbcd300c24219a4941b2ba4ac7b5534f08b56a16a7283ff73ed817b9fb57b855e49f86f407afb7d5a3fdd174b26915b269e60d30b8c6d60a0ee4b19cb38defb72f7044c473ec5708cb2f66cf0789c2b7e3c796c10e29dc0dde29a3aed5332f25cff2cd2e93ba5cd04dbfd985c003aeaa2c8330fdbfbda411dc0f4879c8f7a452d99a3009286f0ddce139c2947b45838e654f2a6d45b874de6a0823f92e201e8208b6f7f813b199b1fe8a303fbd0f886a48332cccf4aba41d7fb91611152b786df03c0dc43f5e7f3333434dccad1cc686adb00dcfe9d80145cb9e2d1561ba5d07b38eb2e6200edd85a1a7ec06d6cd77a69557d814ec1dffb64cf25f9c2cd376271ed26e6adc0"
	outfile := "secrets.json"

	enc, err := hex.DecodeString(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	result, err := decrypt(key, enc)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile(outfile, result, 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("OK! see %s\n", outfile)
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
