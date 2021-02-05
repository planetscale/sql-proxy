Certs are generated with the following commands.


Create a CA:

```bash
openssl req -new -x509 -nodes -days 365 -subj '/CN=my-ca' -keyout ca.key -out ca.crt

# inspect
openssl x509 --in ca.crt -text --noout
```

Create server private and public keys:

```bash
# private key
openssl genrsa -out server.key 2048

# signed public key with a csr
openssl req -new -key server.key -subj '/CN=localhost' -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out server.crt

# inspect
openssl x509 --in server.crt -text --noout
```


Create client private and public keys:

```bash
openssl genrsa -out client.key 2048

# signed public key with a csr
openssl req -new -key client.key -subj '/CN=myorg\/mydb\/mybranch' -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out client.crt

# inspect
openssl x509 --in client.crt -text --noout

```


















