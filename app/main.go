package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/chacha20"
	"io/ioutil"
	"log"
	"net/http"
)

const NONCE_SIZE = 24
var ctx = context.Background()
var KEY []byte
var redisClient *redis.Client

type Payload struct {
	// base64 encoded string of data requested to be encrypted
	Data string	`json:"data"`
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
	var encReq Payload
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
	nonce := make([]byte, NONCE_SIZE)
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

	response := Payload{Data: base64.StdEncoding.EncodeToString(plainBytes)}
	log.Printf("b64 ciphertext: %s\n", response.Data)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func decrypt(w http.ResponseWriter, req *http.Request) {
	log.Printf("decrypt request from %s\n", req.Host)

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
	var decReq Payload
	err := json.NewDecoder(req.Body).Decode(&decReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// decode base64 data into bytes
	ciphertext, err := base64.StdEncoding.DecodeString(decReq.Data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// separate into nonce and actual ciphertext
	nonce := ciphertext[len(ciphertext) - NONCE_SIZE:]
	ciphertext = ciphertext[:len(ciphertext) - NONCE_SIZE]

	// decrypt data
	cipher, err := chacha20.NewUnauthenticatedCipher(KEY, nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cipher.XORKeyStream(ciphertext, ciphertext)

	plaintext := base64.StdEncoding.EncodeToString(ciphertext)
	log.Printf("b64 plaintext: %s\n", plaintext)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(plaintext)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func init() {
	log.SetFlags(log.Ldate | log.Lmicroseconds)

	redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	if _, err := redisClient.Ping(ctx).Result(); err != nil {
		log.Fatalf("error connecting to redis: %s\n", err.Error())
	}

	encKey, err := redisClient.Get(ctx, "key").Result()
	if err == redis.Nil {
		log.Println("encryption key not found in redis")

		KEY = make([]byte, 32)
		if _, err := rand.Read(KEY); err != nil {
			log.Fatalln(err)
		}
		log.Printf("generated encryption key: %x\n", KEY)

		if err = redisClient.Set(ctx, "key", KEY, 0).Err(); err != nil {
			log.Fatalf("error adding encryption key to redis: %s\n", err.Error())
		} else {
			log.Println("encryption key added to redis")
		}
	} else if err != nil {
		log.Fatalf("error getting encryption key from redis: %s\n", err.Error())
	} else {
		KEY = make([]byte, 32)
		KEY = []byte(encKey)

		log.Printf("encryption key loaded from redis: %x\n", KEY)
	}
}

func main() {
	http.HandleFunc("/encrypt", encrypt)
	http.HandleFunc("/decrypt", decrypt)


	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		return 
	}
}
