# Install the server

The only thing to install is the server, unless you decide to connect to a remote server which is also an option. Verba Volant is designed to keep privacy even if the server is compromised. However, in a compromised server even if messages are safe, there are a number of metadata and informations that can leak (IP number above all)


## Dependencies

```
npm install
```

## Run the server

```
npm run dev
```

The server will listen for incoming connection on port 31415 (the pi-port)



The communication is always between Alice and Bob, no more participants are allowed. Is this a limit? Yes. But Verba Volant is not aimed at groups communications. Use other tools instead.

