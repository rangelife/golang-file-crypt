package main

import (
	"bytes"
	"compress/gzip"
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

	ciphertext := "9178a705833130d3c473323b74dd7ebd2ab1fd18cc57e087ed9a925e037b865895601bb60d7d41ee5aaf589d2ea03f8f99ea07cc191f0a1687bbd5a22fa31dfd0b9a58a162c53b88c0ad55a5899bca852435587cd9caad65641c229594edbbb020147857f4b6a58201732797394442a3d7b1ce46926b92ccd54f5be7d805258e3b0151b8e60c810750ebe4d6cc815ba352a2d601c972ef79075a4fe38bdcd6c4f2f6552997cb2bc19fb000d29b945aa2e4cc188087f4fd16f70230a617245f7ee204d1aff5de66a2bc68ace1a722513ae5b71cc4b57fee0db75195a1ad3bd45bc45b1667dabb16490938cfea38243f04ce7b2058a95e354cfb02d91d6ae2655196eceecd8106e4e1b53275869d7f0456cb970ae9e400e03ef4b30fe9162b052969db7c08bab72d765cdac7374d97c8fd38740ebf60334b43567eb6bb98766abc92e0df03df29dbcf1ac30ce3ff55f9af25e86be3eae583c0e72ad8894c92d9dc0591341f3e59b96c6f3dd642a02f3c32799628f9b874d2246e0133ade8e6a815e0735fbff0694a44177e64deba54bcb0f7fc34227293b5f62bb8b653e6c62fc00045891ea732202036626ba9f77c3c7a7ad9a45ba367cfdcea2dc49a3b293fbf14b25d4078890424cef2b0f8cfc3524145716b4e365379b7687b71b8f6f1103eb7f96faeceefef5e4f39ce5e0f9ecae65daf55f50058926da93f11416501e494fc925e5c5c4f66e9de4123daf27727e821cd17e9cf2c0473e6701086506cd52db5d7d9a44da04b4419f387e7f7d7aa72a4dacc3b29efa98b7a62ee0432ce7a0555978e2a463573e1c873a200f3d0e7c4779dfe9e8e38f74615ee222793fc2868e8b643e22b71fe89ae3a7f32bc6d91e88fa143587a3551e7f002b3effb743abc0c7dd023d22f04cde0d7b287869170a16fc7c13a6f2288039b52b73289ca05dcc23cdea17d608138c2ef5b940cd69082a0790726091f9c473f46d5648817b8869cadd13a798ba76dda828dbe843bec31f14db9229ae8c9558a36b93bf8c33814f5b94aff87001e9cfe995d37a9f2695232989fe35101db3231ba478f87627d725c5936f91480b827ac85ec6700f412c147ebdc09163c88888639067d03dbaee1944dee656954e96f73443badf02f84b32aebea96da4c86bbff1fba223f66cac91cfa4191e5ae1aa7d74477db4afddc7dd15954becdbb6da17b21f6dae5b6a39910bc0028566b72ab4dfc650951c18d8aafe81454a0050bb0fa9c6c7922552daf"
	outfile := "out.poo2"

	enc, err := hex.DecodeString(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	squished, err := decrypt(key, enc)
	if err != nil {
		log.Fatal(err)
	}

	result := decompress(squished)

	err = ioutil.WriteFile(outfile, result, 0644)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("OK! see %s\n", outfile)
}

func decompress(input []byte) []byte {
	rdata := bytes.NewReader(input)
	r, err := gzip.NewReader(rdata)
	if err != nil {
		log.Fatal(err)
	}
	s, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}
	return s
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
