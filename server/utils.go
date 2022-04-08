package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strconv"
)

func addLog(str string) {
	// err := ioutil.WriteFile("shiSock-Log.txt", []byte(str+"\n"), 0666)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	f, err := os.OpenFile("shiSock-server-log.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	if _, err = f.WriteString(str + "\n"); err != nil {
		panic(err)
	}
}

func handleError(err error, msg string) {
	_, _, line, _ := runtime.Caller(1)

	if err != nil {
		fmt.Println(msg)
		log.Fatal("Line: "+strconv.Itoa(line)+"-->", err)
	}
}

func encode(data []byte) string {
	hb := base64.StdEncoding.EncodeToString([]byte(data))
	return hb
}

// Decoding the base string to array of bytes
func decode(data string) []byte {
	hb, _ := base64.StdEncoding.DecodeString(data)
	return hb
}

// Generating RSA private key
func generateRsaPrivateKey(size int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Generating RSA public key
func generateRsaPublicKey(privateKey *rsa.PrivateKey) rsa.PublicKey {
	return privateKey.PublicKey
}

// This function can be use encrypt a plain text with rsa algorithm
func rsaEncrypt(publicKey rsa.PublicKey, data []byte) ([]byte, error) {
	// encryptedBytes, err := rsa.EncryptOAEP(
	// 	sha256.New(),
	// 	rand.Reader,
	// 	&publicKey,
	// 	[]byte(data),
	// 	nil)
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, &publicKey, data)
	return encryptedBytes, err
}

// This function can be use decrypt a encrypted text with rsa algorithm
func rsaDecrypt(privateKey rsa.PrivateKey, data []byte) ([]byte, error) {
	// decryptedBytes, err := privateKey.Decrypt(
	// 	nil,
	// 	data,
	// 	&rsa.OAEPOptions{Hash: crypto.SHA256})
	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, &privateKey, data)
	return decryptedBytes, err
}

//  This fucntion is used to dump/serialize the rsa public key
func dumpKey(key *rsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKCS1PublicKey(key), nil
}

// This function is used to load the rsa public key
func loadKey(byteKey []byte) (*rsa.PublicKey, error) {
	key, err := x509.ParsePKCS1PublicKey(byteKey)
	return key, err
}

// Generate fixed size byte array
func generateAesKey(size int) []byte {
	token := make([]byte, size)
	rand.Read(token)
	return token
}

// This fucntion can be used for encrypting a plain text using AES-GCM algorithm
func aesEncryption(key []byte, data []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return cipherText, nil
}

// This fucntion can be used for decrypting the ciphertext encrypted using AES-GCM algorithm
func aesDecryption(key []byte, cipherText []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("1")
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)

	if err != nil {
		fmt.Println("2")
		return nil, err
	}

	noncesize := gcm.NonceSize()
	if len(cipherText) < noncesize {
		fmt.Println("3")
		return nil, err
	}

	nonce, cipherText := cipherText[:noncesize], cipherText[noncesize:]

	plainText, err := gcm.Open(nil, nonce, cipherText, nil)

	if err != nil {
		fmt.Println("4", err.Error())
		return nil, err
	}

	return plainText, nil
}
