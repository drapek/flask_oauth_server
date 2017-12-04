# Introduction

This project show how the oAuth2 works. It implements both, the server and the client.

# Available users
|   login   |   Password    |
|-----------|---------------|
|   alice   |   wonderland  |
|   bob     |   builder     |
|   admin   |   jaturzadze  |
 
 
# Certificate generation
```bash
# self-signed
openssl req -x509 -newkey rsa:1024 -keyout ca.key -out ca.crt -days 365

# generate request
openssl req -newkey rsa:1024 -keyout server.key -out server.csr

# sign request
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

```

### Useful information

* PEM passwords for certificates is 'asdasd12'
