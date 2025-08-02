# Install

The only thing to install is the server, unless you decide to connect to a remote server which is also an option. Verba Volant is designed to keep privacy even if the server is compromised. However, in a compromised server even if messages are safe, there are a number of metadata and informations that can leak (IP number above all)


## Install the server dependencies

```
npm install
```

## Run the server

```
npm run dev
```

The server will listen for incoming connection on port 31415 (the pi-port)



The communication is always between Alice and Bob, no more participants are allowed. Is this a limit? Yes. But Verba Volant is not aimed at groups communications. Use other tools instead.

## Known issues

Check the issues on github project. At the moment the client can't be used as a webapp served via ```http://``` because of browser restrictions that require ```https://``` protocol from remote loading.

As a workaround you can be server via ```file://``` protocol. Save the the folder ```public``` in your computer and click on the index.html file. The client is a vanilla static page which loads his styles and his javascript. No other deps required. For a better experience I recommend to load index.html in a first browser window (which will be Alice) and then use a different browser or browser profile to load as Bob.

