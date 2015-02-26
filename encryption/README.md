## encryption - Demonstration of NodeJS crypto-signing

This NodeJS app is a demonstration of using public-key encryption to sign a message, send it, and then have the receiver verify the signed message.

Currently uses the `keypair` NodeJS package to generate keypairs, and uses the NodeJS `crypto` package to perform signing/verification.



### Running multiple instances on same host

For multiple nodes on the same host, you will need to patch the node-discover package. Until the source repo is fixed or forked, the easiest way is to:

- Ensure you have a `node_modules` directory by doing `npm install`
- Edit `node_modules/node-discover/lib/network.js` by replacing:

>	`self.socket = dgram.createSocket('udp4');`

with:

>	`self.socket = dgram.createSocket({type: 'udp4', reuseAddr:true});`

If you get an EADRINUSE error from node-discover, it means that you are using an unpatched version.


### How to run it

If you run with two instances (see `test.sh`), then Node0 will be the Sender, Node1 will be Receiver.

Additional instances (Node2+) will behave as Forgers.


