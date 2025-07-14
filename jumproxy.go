package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

var (
	listenPort  int
	keyfile     string
	destination string
	port        string
	key         []byte
)

// WORKS
func encryptAndSend(proxy net.Conn) {

	// Passphrase retrieval
	file, err := os.Open(keyfile)
	if err != nil {
		//log.Print(err)

	}
	defer file.Close()
	buf := make([]byte, 1024)
	n, err := file.Read(buf)
	if err != nil {
		//log.Print(err)

	}
	passphrase := string(buf[:n])

	// pre-set 8-byte salt
	salt := []byte("helloall")

	// use pbkdf2 to derive aes 256 key
	key = pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		//log.Print(err)

	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		//log.Print(err)

	}

	// Create a random nonce and send it in plaintext form with the encrypted data
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		//log.Print(err)

		return
	}
	//log.Print(nonce)

	_, err = proxy.Write(nonce)
	if err != nil {
		//log.Print(err)

		return
	}
	buffer := make([]byte, 8096)
	for {
		n, err := os.Stdin.Read(buffer)
		if err != nil {
			if err == io.EOF {
				//log.Print("sent from client: " + string(buffer[:n]))

				break
			}
			//log.Print(err)

			os.Exit(1)
		}
		// encrypt the current chunk and send it
		ciphertext := gcm.Seal(nil, nonce, buffer[:n], nil)
		//log.Print(len(ciphertext))

		//log.Print("sent from client: " + string(buffer[:n]))
		err = binary.Write(proxy, binary.BigEndian, uint32(len(ciphertext)))
		if err != nil {
			//log.Print(err)
			return
		}

		_, err = proxy.Write(ciphertext)
		if err != nil {
			//log.Print(err)

			return
		}
	}
}

// WORKS
func decryptAndPrint(proxy net.Conn) {
	// Passphrase retrieval
	file, err := os.Open(keyfile)
	if err != nil {
		//log.Print(err)

	}
	defer file.Close()
	buf := make([]byte, 1024)
	n, err := file.Read(buf)
	if err != nil {
		//log.Print(err)
	}
	passphrase := string(buf[:n])

	// pre-set 8-byte salt
	salt := []byte("helloall")

	// use pbkdf2 to derive aes 256 key
	key = pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		//log.Print(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		//log.Print(err)
	}

	// Retrieve nonce from proxy output
	nonce := make([]byte, gcm.NonceSize())
	if _, err = proxy.Read(nonce); err != nil {
		//log.Print(err)
		return
	}
	//log.Print(nonce)

	for {
		var cipherLen uint32
		err := binary.Read(proxy, binary.BigEndian, &cipherLen)
		if err != nil {
			if err == io.EOF {
				//log.Print("EOF")

				break
			}
			//log.Print(err)

			os.Exit(1)
		}
		//log.Print(cipherLen)
		buffer := make([]byte, cipherLen)
		n, err = proxy.Read(buffer)
		if err != nil {
			if err == io.EOF {
				//log.Print("EOF")

				break
			}
			//log.Print(err)

			os.Exit(1)
		}
		//log.Print(n)

		// Decrypt the current chunk and send it to sshd
		plaintext, err := gcm.Open(nil, nonce, buffer[:n], nil)
		if err != nil {
			//log.Print(err)

			continue
		}
		//log.Print("relayed to server: " + string(buffer[:n]))

		_, err = os.Stdout.Write(plaintext)
		if err != nil {
			//log.Print(err)

			return
		}
	}
}

// WORKS
func decryptAndRelay(client, server net.Conn) {

	// Passphrase retrieval
	file, err := os.Open(keyfile)
	if err != nil {
		//(log.Print(err))

	}
	defer file.Close()
	buf := make([]byte, 1024)
	n, err := file.Read(buf)
	if err != nil {
		//(log.Print(err))

	}
	passphrase := string(buf[:n])

	// pre-set 8-byte salt
	salt := []byte("helloall")

	// use pbkdf2 to derive aes 256 key
	key = pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)
	//(log.Print("key: " + string(key)))
	block, err := aes.NewCipher(key)
	if err != nil {
		//(log.Print(err))

	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		//(log.Print(err))

	}

	// Retrieve nonce from client output
	nonce := make([]byte, gcm.NonceSize())
	if _, err = client.Read(nonce); err != nil {
		//log.Print(err)

		return
	}
	//log.Print("nonce: " + string(nonce))
	for {
		var cipherLen uint32
		err := binary.Read(client, binary.BigEndian, &cipherLen)
		if err != nil {
			if err == io.EOF {
				//log.Print("EOF")

				break
			}
			//log.Print(err)

			os.Exit(1)
		}
		//log.Print(cipherLen)
		buffer := make([]byte, cipherLen)
		n, err = client.Read(buffer)
		if err != nil {
			if err == io.EOF {
				//log.Print("EOF")

				break
			}
			//log.Print(err)

			os.Exit(1)
		}
		//(log.Print(n))

		// Decrypt the current chunk and send it to sshd
		plaintext, err := gcm.Open(nil, nonce, buffer[:n], nil)
		if err != nil {
			//log.Print(err)

			continue
		}
		//(log.Print("relayed to server: " + string(plaintext)))

		_, err = server.Write(plaintext)
		if err != nil {
			//(log.Print(err))

			return
		}
	}
}

// WORKS
func encryptAndRelay(client, server net.Conn) {
	// Passphrase retrieval
	file, err := os.Open(keyfile)
	if err != nil {
		//(log.Print(err))

	}
	defer file.Close()
	buf := make([]byte, 1024)
	n, err := file.Read(buf)
	if err != nil {
		//(log.Print(err))

	}
	passphrase := string(buf[:n])

	// pre-set 8-byte salt
	salt := []byte("helloall")

	// use pbkdf2 to derive aes 256 key
	key = pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)
	//(log.Print("key:" + string(key)))

	block, err := aes.NewCipher(key)
	if err != nil {
		//(log.Print(err))

	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		//(log.Print(err))

	}

	// Create a random nonce and send it in plaintext form with the encrypted data
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		//(log.Print(err))

		return
	}
	//(log.Print("nonce: " + string(nonce)))

	_, err = client.Write(nonce)
	if err != nil {
		//(log.Print(err))

		return
	}
	buffer := make([]byte, 8096)
	for {
		n, err := server.Read(buffer)
		if err != nil {
			if err == io.EOF {
				//(log.Print("sent from client: " + string(buffer[:n])))

				break
			}
			//(log.Print(err))

			os.Exit(1)
		}
		// encrypt the current chunk and send it
		ciphertext := gcm.Seal(nil, nonce, buffer[:n], nil)
		//(log.Print(len(ciphertext)))

		//(log.Print("relayed to client: " + string(ciphertext)))

		err = binary.Write(client, binary.BigEndian, uint32(len(ciphertext)))
		if err != nil {
			log.Print(err)
			return
		}
		_, err = client.Write(ciphertext)
		if err != nil {
			//(log.Print(err))
			return
		}
	}
}

// WORKS
func main() {
	// Parse arguments
	flag.IntVar(&listenPort, "l", 0, "Specify a port for the reverse-proxy to listen on")
	flag.StringVar(&keyfile, "k", "mykey", "Specify a file which contains the passphrase to use in AES-256 encryption")
	flag.Parse()

	// Dest and Port
	destination = flag.Arg(0)
	port = flag.Arg(1)

	if listenPort == 0 {
		//Client mode

		proxyConn, err := net.Dial("tcp", destination+":"+port)
		if err != nil {
			//log.Print(err)
			return
		}
		defer proxyConn.Close()
		go encryptAndSend(proxyConn)
		decryptAndPrint(proxyConn)
	} else {
		// Proxy mode
		//log.Print("Proxy listening on port " + strconv.Itoa(listenPort) + " relaying to " +
		//destination + ":" + port)

		listener, err := net.Listen("tcp", ":"+strconv.Itoa(listenPort))
		if err != nil {
			//log.Print(err)
			return
		}
		defer listener.Close()

		for {
			clientConn, err := listener.Accept()
			if err != nil {
				//log.Print(err)
				continue
			}
			defer clientConn.Close()

			serverConn, err := net.Dial("tcp", destination+":"+port)
			if err != nil {
				//log.Print(err)
				return
			}
			defer serverConn.Close()

			go decryptAndRelay(clientConn, serverConn)
			go encryptAndRelay(clientConn, serverConn)
		}
	}
}
