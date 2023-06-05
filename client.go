package filetransfer;
// Cryptography imports 
import (
	aes 		"crypto/aes"
	hash   		"crypto/sha256"
	rand   		"crypto/rand";
	rsa 		"crypto/rsa";
);
// Formatting imports
import (
	binary      "encoding/binary";
	bytes  		"bytes";
	hex  		"encoding/hex";
	regexp		"regexp" // removes blank bytes from fileSize and fileName
	strconv 	"strconv";
);
// Other imports 
import (
	time  		"time" // appends current date to recieved filename
	sync 		"sync";
	fmt 		"fmt";
	net  		"net";
	os  		"os";
	io   		"io";
);
var wg_client sync.WaitGroup;
/**
 * FetchFromBroadcast recieves a file and decrypts it.
 * 	> decrypts AES key using public key.
 *  > decrypts message using AES key.
 **/
func FetchFromBroadcast(address string) error{
	// Goroutine communication channels 
	connection_chan := make(chan net.Conn, 2);
	privatekey_chan := make(chan *rsa.PrivateKey, 1);
	packet_chan := make(chan []byte, 1);
	message_chan := make(chan []byte, 1);
	var err error;
	err_ptr := &err; // Used to pass errors back from gorountines
	// Setting up connection
	wg_client.Add(1);
	go setupClientConnection(address, connection_chan, err_ptr);
	wg_client.Wait();
	if *err_ptr != nil{
		return *err_ptr;
	}
	// Transmitting public key
	wg_client.Add(1);
	go transmitPublicKey(<-connection_chan, privatekey_chan, err_ptr);
	wg_client.Wait();
	if *err_ptr != nil{
		return *err_ptr;
	}
	// Listening for file
	wg_client.Add(1);
	go recieveBytes(<-connection_chan, packet_chan, err_ptr);
	wg_client.Wait();
	if *err_ptr != nil{
		return *err_ptr;
	}
	// Decrypting the file
	decryptPacket(<-packet_chan, <-privatekey_chan, message_chan, err_ptr);
	if *err_ptr != nil{
		return *err_ptr;
	}
	return nil;
}
/**
 * This method decrypts the AES key using the private AES key, 
 * and decrypts the message using the AES key. 
 **/
func decryptPacket(packet []byte, privatekey *rsa.PrivateKey, message_chan chan []byte, err_ptr *error){
	fileSizeBytes := packet[0:16];
	reg, _ := regexp.Compile("[^0-9 ]+")
	fileSizeInt, _ := strconv.ParseInt(
		reg.ReplaceAllString(string(fileSizeBytes), ""), 
		10, 
		64,
	);
	fmt.Println("Recieving file size \t\t|", fileSizeInt, " bytes");
	fileNameBytes := packet[16:32];
	encryptedAESKey := packet[32:32+AES_KEY_BYTES]
	encryptedMessage := packet[32+AES_KEY_BYTES:]
	// Decrypting AES key
	h := hash.New();
	decryptedAESKey, err := rsa.DecryptOAEP(h, rand.Reader, privatekey, encryptedAESKey, nil);
	if err != nil {
		*err_ptr = err;
		return;
	}
	AESCipher, err := aes.NewCipher(decryptedAESKey);
	if err != nil {
		*err_ptr = err;
		return;
	}
	// Reading file and decrypting with AES key
	messageReader := bytes.NewReader(encryptedMessage);
	messageBuffer := make([]byte, BUFFERSIZE);
	decryptedBuffer := make([]byte, BUFFERSIZE);
	decryptedMessage := make([]byte, 0);
	for{
		_, err := messageReader.Read(messageBuffer)
		AESCipher.Decrypt(decryptedBuffer, messageBuffer);
		decryptedMessage = append(decryptedMessage, decryptedBuffer...);
		if err == io.EOF{
			break;
		} else if err != nil {
			*err_ptr = err;
			return;
		}
	}
	saveFile(string(fileNameBytes), decryptedMessage[0:fileSizeInt], err_ptr);
	return;
}
/**
 * This method saves the recieved (decrypted) file.
 **/
func saveFile(fileName string, fileData []byte, err_ptr *error){
	reg, _ := regexp.Compile("[^A-Za-z0-9.]+")
	currentTime := time.Now()
	fileName_2 := currentTime.Format("2006_01_02")+ "_" + reg.ReplaceAllString(string(fileName), "");
	fmt.Println("Saving file \t\t\t|", fileName_2);
	err := os.WriteFile(string(fileName_2), fileData, 0644);
	if err != nil {
		*err_ptr = err;
	}
	return;
}
/**
 * This method connects to the server.
 **/
func setupClientConnection(address string, connection_chan chan net.Conn, err_ptr *error){
	defer wg_client.Done();
	defer close(connection_chan);
	connection, err := net.Dial("tcp", address);
	if err != nil{
		*err_ptr = err;
		return;
	}
	fmt.Println("Found broadcast server \t\t|", connection.RemoteAddr());
	connection_chan <- connection;
	connection_chan <- connection;
	return;
}
/**
 * This method transmits the public key to the server.
 * Public key is used to encrypt AES key in delivered packet.
 **/
func transmitPublicKey(connection net.Conn, privatekey_chan chan *rsa.PrivateKey, err_ptr *error){
	defer wg_client.Done();
	defer close(privatekey_chan);

	PublicKey, PrivateKey, err := generateRSAKeyPair();
	if err != nil{
		*err_ptr = err;
		return;
	}
	privatekey_chan <- PrivateKey;
	
	bufferPublicKeyE := make([]byte, 128);
	binary.LittleEndian.PutUint64(bufferPublicKeyE, uint64(PublicKey.E));
	bufferPublicKeyN := PublicKey.N.Bytes();

	fmt.Println("Transmitting public key \t|", connection.RemoteAddr());
	fmt.Println("Public Key E \t\t\t| ", hex.EncodeToString(bufferPublicKeyE)[0:10], "...");
	fmt.Println("Public Key N \t\t\t| ", hex.EncodeToString(bufferPublicKeyN)[0:10], "...");
	connection.Write(bufferPublicKeyE);
	connection.Write(bufferPublicKeyN);
	return;
}
/**
 * Recieve bytes from server.
 **/
func recieveBytes(connection net.Conn, packet_chan chan []byte, err_ptr *error){
	defer wg_client.Done();
	defer close(packet_chan);
	defer connection.Close();

	recievedPacket := make([]byte, 0);
	receiveBuffer := make([]byte, BUFFERSIZE);
	for{
		_, err := connection.Read(receiveBuffer);
		if err == io.EOF{
			break;
		} else if err != nil {
			*err_ptr = err;
			return;
		}
		recievedPacket = append(recievedPacket, receiveBuffer...);
	}
	packet_chan <- recievedPacket;
	return;
}
/**
 * Generates a key length of 128 bits
 **/
func generateRSAKeyPair() (rsa.PublicKey, *rsa.PrivateKey, error){
	var err error;
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024);
	if err != nil{
		return rsa.PublicKey{}, &rsa.PrivateKey{}, err;
	}
	publicKey := (privateKey.PublicKey);
	return publicKey, privateKey, nil;
}