package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"
)

type Vectors struct {
	TestVectors []Vector `json:"vectors"`
}

type Vector struct {
	Name          string    `json:"name"`
	Pattern       string    `json:"pattern"`
	DH            string    `json:"dh"`
	Cipher        string    `json:"cipher"`
	Hash          string    `json:"hash"`
	InitPrologue  string    `json:"init_prologue"`
	InitEphemeral string    `json:"init_ephemeral"`
	RespPrologue  string    `json:"resp_prologue"`
	RespEphemeral string    `json:"resp_ephemeral"`
	Messages      []Message `json:"messages"`
	HandshakeHash string    `json:"handshake_hash"`
}

type Message struct {
	Payload    string `json:"payload"`
	Ciphertext string `json:"ciphertext"`
}

func TestSerialization(t *testing.T) {
	file, err := os.Open("cacophony.txt")
	if err != nil {
		t.Errorf("failed to open test file")
		return
	}
	blob, err := ioutil.ReadAll(file)
	if err != nil {
		t.Errorf("failed to read the test file")
		return
	}
	vectors := new(Vectors)
	err = json.Unmarshal(blob, &vectors)
	if err != nil {
		t.Errorf("failed to unmarshal input file")
		return
	}
	log.Printf("Vector 1 Name: %v\n", vectors.TestVectors[0].Name)
}
