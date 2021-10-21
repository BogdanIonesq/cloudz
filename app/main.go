package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/go-redis/redis/v8"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/chacha20"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const NONCE_SIZE = 24
var (
	ctx = context.Background()
	KEY []byte
	redisClient *redis.Client
	encryptOps = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cloudz_encrypt_operations",
		Help: "The total number of successful encryption operations",
	})
	decryptOps = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cloudz_decrypt_operations",
		Help: "The total number of successful decryption operations",
	})
	errorOps = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cloudz_errors",
		Help: "The total number of errors produced",
	})
)

type Payload struct {
	// base64 encoded string of data requested to be encrypted/decrypted
	Data string	`json:"data"`
}

func encrypt(w http.ResponseWriter, req *http.Request) {
	log.Printf("encrypt request from %s\n", req.Host)

	// print request body
	buf, bodyErr := ioutil.ReadAll(req.Body)
	if bodyErr != nil {
		errorOps.Inc()
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
		errorOps.Inc()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	plainBytes, err := base64.StdEncoding.DecodeString(encReq.Data)
	if err != nil {
		errorOps.Inc()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate random IV
	nonce := make([]byte, NONCE_SIZE)
	if _, err := rand.Read(nonce); err != nil {
		errorOps.Inc()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// encrypt data
	cipher, err := chacha20.NewUnauthenticatedCipher(KEY, nonce)
	if err != nil {
		errorOps.Inc()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cipher.XORKeyStream(plainBytes, plainBytes)

	// add nonce to end of ciphertext
	plainBytes = append(plainBytes, nonce...)

	// generate response containing ciphertext
	response := Payload{Data: base64.StdEncoding.EncodeToString(plainBytes)}
	log.Printf("b64 ciphertext: %s\n", response.Data)

	// add ciphertext hash to redis
	ciphertextHash := sha256.Sum256([]byte(response.Data))

	if err := redisClient.SAdd(ctx, "known_hashes", ciphertextHash[:]).Err(); err != nil {
		log.Printf("encrypt error: %s\n", err.Error())
		errorOps.Inc()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		log.Printf("ciphertext hash added to redis: %x\n", ciphertextHash)
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		errorOps.Inc()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		encryptOps.Inc()
	}
}

func decrypt(w http.ResponseWriter, req *http.Request) {
	log.Printf("decrypt request from %s\n", req.Host)

	// print request body
	buf, bodyErr := ioutil.ReadAll(req.Body)
	if bodyErr != nil {
		errorOps.Inc()
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
		errorOps.Inc()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// check if data is known
	ciphertextHash := sha256.Sum256([]byte(decReq.Data))

	ok, err := redisClient.SIsMember(ctx, "known_hashes", ciphertextHash[:]).Result()
	if err != nil {
		log.Printf("decrypt error: %s\n", err.Error())
		errorOps.Inc()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if !ok {
		log.Println("request ciphertext is unkown")
		errorOps.Inc()
		http.Error(w, "invalid data", http.StatusBadRequest)
		return
	}

	// decode base64 data into bytes
	ciphertext, err := base64.StdEncoding.DecodeString(decReq.Data)
	if err != nil {
		errorOps.Inc()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// separate into nonce and actual ciphertext
	nonce := ciphertext[len(ciphertext) - NONCE_SIZE:]
	ciphertext = ciphertext[:len(ciphertext) - NONCE_SIZE]

	// decrypt data
	cipher, err := chacha20.NewUnauthenticatedCipher(KEY, nonce)
	if err != nil {
		errorOps.Inc()
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
	} else {
		decryptOps.Inc()
	}
}

func init() {
	log.SetFlags(log.Ldate | log.Lmicroseconds)

	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		log.Fatalln("error: env variable REDIS_HOST not set")
	}

	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		log.Fatalln("error: env variable REDIS_PORT not set")
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisHost + ":" + redisPort,
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
	http.Handle("/metrics", promhttp.Handler())


	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		return 
	}
}
