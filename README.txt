Aawab Mahmood
Plugboard Proxy

No external libraries used, though might have to go download "golang.org/x/crypto/pbkdf2"

go.mod included for anything necessary

no need to run go build, can just use go run 

-----------------------

For server:
cd to project directory, then run the following, replacing localhost with another address if needed:

go run jumproxy.go -k mykey -l 2222 localhost 22

-----------------------

For client(s):
cd to project directory, then run the following, replacing user and address accordingly:

ssh -o "ProxyCommand go run jumproxy.go -k mykey localhost 2222" user@addr

-----------------------

Implementation:

Everything is done in one file, jumproxy.go. I've separated the functionality in the main() function
along with two encrypt/decrypt functions for each of the proxy/client respectively, for a total of 4
helper functions. Details below:

encryptAndSend(proxy net.Conn) - encrypts and sends data from stdin of a single client to the proxy
decryptAndPrint(proxy net.Conn) - decrypts and sends data from proxy to stdout of a single client
decryptAndRelay(client, server net.Conn) - decrypts and relays data from a single client to server
encryptAndRelay(client, server net.Conn) - encrypts and relays data from server to a single client

The main() function parses the arguments and stores many in global variables. I then check whether
the listen port has been input(i.e is not the default of 0) and go into client or server mode
accordingly. Comments have been placed in numerous places to improve readability. 

Client mode: 
Dials up to the proxy address, and once established runs a separate goroutine for encryptAndSend()
to allow sending data at any time while constantly waiting on received data from decryptAndPrint().

Proxy mode:
Opens up the listener, and starts a for loop that blocks until client connections. It then spawns
a new Dial connection to the actual server and uses both the client and server connections in the 
goroutined functions decryptAndRelay() and encryptAndRelay() to allow constant relaying of data from
both ends at any time. 

Encryption/Decryption:
I used pbkdf2, aes in gcm mode, a pre-set salt value, and the same key for all clients. The key was
generated using the passphrase found in the file noted in the -k argument(mykey in our case). A 
random nonce was then generated according to the gcm block's nonce size, and sent over to the
receiver to allow for decryption at that end. The input was buffered and read in from the source 
and then encrypted. The ciphertext's length was encoded in BigEndian and sent over to the
receiver in order to grab and use to correctly set their buffer length to successfully decrypt
the ciphertext now that they are able to grab the correct length necessary. Thank you to Professor
on piazza for the quick replies both to me and other students, I wouldn't have tried the prefix
length setting otherwise! It fixed my errors from proxy->client encryption/decryption. 

