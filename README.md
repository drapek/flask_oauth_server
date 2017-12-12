# Introduction

This project show how the oAuth2 works. It implements both, the server and the client.

## Available users
|   login   |   Password    |
|-----------|---------------|
|   alice   |   wonderland  |
|   bob     |   builder     |
|   admin   |   jaturzadze  |
 
## How to use it?

1. Run the server and the client
```bash
python server/server.py
python clinet/clinet.py
```
2. Open the web browser and type localhost:8888 (oauth client)
3. Input your credentials on redirected site (oauth server)
4. Allow permissions
5. When you see page with token, go to the index page of the client (localhost:8888)
6. You should see your user data on the client page
 
## Requirements
* Python >= 3.5
* python packages from requrements.txt