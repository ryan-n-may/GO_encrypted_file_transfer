# GO_encrypted_file_transfer
A simple GO script to transfer files via TCP.  Uses AES and RSA encryption

This script broadcasts a packet that contains the file (encrypted with AES cipher), and a header.  The header contains the file name and file size (bytes) (unencrypted), as well as the AES key (encrypted with the RSA public key of the reciever). 

```go
  var err = server.BroadcastFile("xx.xx.xx.xx:27001", "file.txt", "password");
  var err = client.FetchFromBroadcast("xx.xx.xx.xx:27001");
```

## Packet structure
![packet structure image](https://github.com/ryan-n-may/GO_encrypted_file_transfer/blob/main/packet.png)

## Key exchange 
![key exchange image](https://github.com/ryan-n-may/GO_encrypted_file_transfer/blob/main/keyexchange.drawio.png)
