package filetransfer;
// Cryptography imports
import (
	rand   		"crypto/rand";
	aes    		"crypto/aes";
	hash  		"crypto/sha256";
	rsa  		"crypto/rsa";
);
// Formatting imports 
import (
	binary 		"encoding/binary";
	hex  		"encoding/hex";
	strconv 	"strconv";
	bytes 		"bytes";
)
// Other imports
import (
	big  		"math/big";
	net  		"net";
	os  		"os";
	io   		"io";
	sync   		"sync";
	fmt 		"fmt";
);
const BUFFERSIZE = 16;
const AES_KEY_BYTES = 128;
const FILE_INFO_BYTES = 64;
var wg sync.WaitGroup;
/**
 * Broadcast file handles the broadcasting of a file given by a filepath, 
 * and encrypted with AES via a passphrase. 
 * Broadcast file recieves a public key from a reciever, and packages 
 * the encrypted message with an RSA encryption of the AES key. 
 **/
func BroadcastFile(address, filepath, passphrase string) error{
	var connection_chan = make(chan net.Conn, 2);
	var pub_chan = make(chan *rsa.PublicKey, 1);
	var packet_chan = make(chan []byte, 1);

	var err error;
	err_ptr := &err;

	wg.Add(1);
	go setupConnection(address, passphrase, connection_chan, err_ptr);
	wg.Wait();
	if  *err_ptr != nil  {
		return *err_ptr;
	}
	// Fetch public key listens for public key bytes from recieving client. 
	wg.Add(1);
	go fetchPublicKey(<-connection_chan, pub_chan);
	wg.Wait();
	// Sending the encrypted file and file stats to the client. 
	wg.Add(1);
	go constructPacket(filepath, passphrase, <-pub_chan, packet_chan, err_ptr);
	wg.Wait();
	if  *err_ptr != nil  {
		return *err_ptr;
	}
	wg.Add(1);
	go sendFile(<-connection_chan, <-packet_chan, err_ptr);
	wg.Wait();
	if  *err_ptr != nil  {
		return *err_ptr;
	}
	return nil;
}
/**
 * fetchPublicKey listens for the public key transmission from the client
 * reciever. 
 **/
func fetchPublicKey(connection net.Conn, pub_chan chan *rsa.PublicKey){
	defer wg.Done();
	defer close(pub_chan);
	EBuffer := make([]byte, 128);
	NBuffer := make([]byte, 128);
	connection.Read(EBuffer);
	connection.Read(NBuffer);
	var publicKey rsa.PublicKey;
	publicKey.N = new(big.Int).SetBytes(NBuffer);
	publicKey.E = int(binary.LittleEndian.Uint64(EBuffer));
	pub_chan <- &publicKey;
	fmt.Println("Public Key E \t\t| ", hex.EncodeToString(EBuffer)[0:10], "...");
	fmt.Println("Public Key N \t\t| ", hex.EncodeToString(NBuffer)[0:10], "...");
	return;
}
/**
 * This method sends the encrypted packet.
 **/
func sendFile(connection net.Conn, packet []byte, err_ptr *error){
	defer wg.Done();
	fmt.Println("Sending file...");
	packetReader := bytes.NewReader(packet);
	for {
		sendBuffer := make([]byte, BUFFERSIZE);
		_, err := packetReader.Read(sendBuffer);
		if err == io.EOF{
			break;
		} else if err != nil {
			*err_ptr = err;
			return;
		}
		connection.Write(sendBuffer);
	}
	return;
}
/**
 * this method constructs the packet 
 * 		(16 bytes) 	fileSize
 * 		(16 bytes) 	fileName
 * 		(128 bytes) AES key (encrypted with RSA public key)
 * 		(... bytes) MESSAGE (encrypted with AES key)
 **/
func constructPacket(filepath, passphrase string, 
	pub *rsa.PublicKey,
	packet_chan chan []byte,
	err_ptr *error,
	){
	defer close(packet_chan);
	defer wg.Done();
	// Opening file and getting file stats
	fileObj, err := os.Open(filepath);
	if err != nil {
		*err_ptr = err;
		return;
	}
	fileInfo, err := fileObj.Stat();
	if err != nil {
		*err_ptr = err;
		return;
	}
	// Reading message plaintext
	message := make([]byte, fileInfo.Size());
	_, err = fileObj.Read(message); 
	if err != nil {
		*err_ptr = err;
		return;
	}
	// Generating AES cipher 
	h := hash.New();
	h.Write([]byte(passphrase));
	AESKey := h.Sum(nil);
	AESCipher, err := aes.NewCipher(AESKey);
	if err != nil {
		*err_ptr = err;
		return;
	}
	// Encrypting AES message
	encryptedMessage := make([]byte, 0);
	messageReader := bytes.NewReader(message);
	messageBuffer := make([]byte, BUFFERSIZE);
	encryptedBuffer := make([]byte, BUFFERSIZE);
	for {
		_, err := messageReader.Read(messageBuffer);
		AESCipher.Encrypt(encryptedBuffer, messageBuffer);
		if err == io.EOF{
			break;
		} else if err != nil {
			*err_ptr = err;
			return;
		}
		encryptedMessage = append(encryptedMessage, encryptedBuffer...);
	}
	// Encrypting AES key with public key
	encryptedAESKey, err := rsa.EncryptOAEP(h, rand.Reader, pub, AESKey, nil);
	if err != nil {
		*err_ptr = err;
		return;
	}
	// Constructing complete message
	fileSize16Bytes := make([]byte, 16-len([]byte(strconv.FormatInt(fileInfo.Size(), 10))))
	fileSize16Bytes = append(fileSize16Bytes, []byte(strconv.FormatInt(fileInfo.Size(), 10))...);

	fileName16Bytes := make([]byte, 16-len(fileInfo.Name()));
	fileName16Bytes = append(fileName16Bytes, fileInfo.Name()...);

	completeMessage := make([]byte, 0);
	completeMessage = append(completeMessage, fileSize16Bytes...);
	completeMessage = append(completeMessage, fileName16Bytes...);
	completeMessage = append(completeMessage, encryptedAESKey...);
	completeMessage = append(completeMessage, encryptedMessage...);
	// Saving encrypted message (for debugging)
	fmt.Println("Packet length \t\t| ", len(completeMessage), " bytes");
	packet_chan <- completeMessage;
	return;
}
/**
 * Listens for connections to server.
 **/
func setupConnection(address, passphrase string, 
	connection_chan chan net.Conn,
	err_ptr *error,
	){
	fmt.Println("Setting up connection \t| ", address);
	defer wg.Done();
	defer close(connection_chan);
	listener, err := net.Listen("tcp", address);
	if err != nil {
		*err_ptr = err;
		return;
	}
	defer listener.Close();
	var connection net.Conn;
	for connection == nil {
		connection, err = listener.Accept();
		if err != nil{
			*err_ptr = err;
			return
		}
	}
	fmt.Println("Reciever connected \t| ", connection.RemoteAddr());
	connection_chan <- connection;
	connection_chan <- connection;
	return;
}
