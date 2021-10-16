package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/chacha20"
	"io/ioutil"
	"log"
	"net/http"
)

var KEY []byte

type EncryptRequest struct {
	// base64 encoded string of data requested to be encrypted
	Data string	`json:"data"`
}

type EncryptResponse struct {
	// base64 encoded string of encrypted data
	Ciphertext string `json:"ciphertext"`
}

func encrypt(w http.ResponseWriter, req *http.Request) {
	log.Printf("encrypt request from %s\n", req.Host)

	// print request body
	buf, bodyErr := ioutil.ReadAll(req.Body)
	if bodyErr != nil {
		http.Error(w, bodyErr.Error(), http.StatusInternalServerError)
		return
	}
	reader1 := ioutil.NopCloser(bytes.NewBuffer(buf))
	reader2 := ioutil.NopCloser(bytes.NewBuffer(buf))
	req.Body = reader2

	log.Printf("request body: %q\n", reader1)

	// decode request
	var encReq EncryptRequest
	err := json.NewDecoder(req.Body).Decode(&encReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	plainBytes, err := base64.StdEncoding.DecodeString(encReq.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate random IV
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// encrypt data
	cipher, err := chacha20.NewUnauthenticatedCipher(KEY, nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cipher.XORKeyStream(plainBytes, plainBytes)

	// add nonce to end of ciphertext
	plainBytes = append(plainBytes, nonce...)

	response := EncryptResponse{Ciphertext: base64.StdEncoding.EncodeToString(plainBytes)}
	log.Printf("response ciphertext: %s\n", response.Ciphertext)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

}

func init() {
	log.SetFlags(log.Ldate | log.Lmicroseconds)

	KEY = make([]byte, 32)
	if _, err := rand.Read(KEY); err != nil {
		panic(err)
	}
	log.Printf("generated encryption key: %x\n", KEY)
}

func main() {
	http.HandleFunc("/encrypt", encrypt)

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		return 
	}
}
