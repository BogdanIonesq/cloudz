## cloudz :cloud:

A straightforward project for University of Bucharest showcasing a cloud native application with logging and metrics workflows.

---

### About

The [app](app) is written in Golang and supports encrypting and decrypting base64 encoded strings with the [ChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) cryptographic algorithm, featuring [redis](https://redis.io/) storing.

To encrypt arbitrary data:
* encode the data using base64:
```
$ echo -n "secret_data" | base64
```
* POST the encoded string to the `/encrypt` endpoint:
```
$ curl -X POST http://<APP_IP>:8080/encrypt -H 'Content-Type: application/json' -d '{"data":"<BASE64_DATA>"}'
```
The server will:

    * decode the base64 encoded data to bytes
    * encrypt the bytes with ChaCha20 with a 24 bytes nonce
    * create the ciphertext by concatenating the resulting encrypting bytes and the nonce bytes
    * store the SHA256 hash of the ciphertext to redis
    * return the base64 encoded ciphertext to the client

To decrypt previosuly encrypted data:
* execute a GET request on the `/decrypt` endpoint:
```
$ curl -X GET http://<APP_IP>:8080/decrypt -H 'Content-Type: application/json' -d '{"data":"<BASE64_DATA>"}'
```
The server will:

    * compute the SHA256 hash of the data and check if it is present in redis
    * if it is found in redis, decrypt the data to obtain the plaintext
    * return the base64 encoded plaintext to the client

The server also has a third endpoint at `/metrics`, which serves [Prometheus](https://prometheus.io/) metrics. In addition to the default Go metrics, the following counters are available:
* `cloudz_encrypt_operations`: the total number of successful encryption operations
* `cloudz_decrypt_operations`: the total number of successful decryption operations
* `cloudz_errors`: the total number of errors encountered on either encryption or decryption operations

Logs generated by the application are collected by a Fluent Bit sidecar and forwarded to an Elasticsearch instance.

### Deployment

Build the application Docker image:
```
$ docker build -t cloudz:latest .
```

Create a local 3 node Kubernetes cluster with kind:
```
$ cd kind/
$ kind create cluster --config=config.yaml
$ kubectl cluster-info --context kind-kind
```

Load the application Docker image into the cluster nodes:
```
$ kind load docker-image cloudz:latest
```

Deploy the Prometheus, Elasticsearch and Kibana instances:
```
$ cd kubernetes/
$ kubectl apply -f monitoring.yaml
```

Deploy the application:
```
$ cd kubernetes/
$ kubectl apply -f app.yaml
```



