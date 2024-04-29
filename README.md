## Group members and contributions each made

Kush Patel-wrote the starter code, and went to goffman for help with pickling the data structure into bytes so it can be sent to the other client files and the servers

Daylan Stoica-edited most of the starter code and added threading so it would accept multiple clients

Ryan Phillips-edited some of the starter code and added hashing which would create a digital signature

Mason Chiang-modified the decryption part written in the starter code, so it would decrypt all the files that was sent from the client and display all the decrypted contents

Edmarck Sosa-modified the encryption part written in the starter code, so it would encrypt all the files in the the directory that is being sent to the other clients and the server

















### Project Description

This project is a secure file sharing system in which there are clients and a server, the server accepts multiple clients at a time, and when a client wants to share a file, the client sends the file to the server and any other clients listening to the server, and the other clients receive the file in which the server broadcasts the message containing the file, and the server displays the contents of the file. The services the project provides are encryption, hashing, confidentiality, and digital signature in which before sending, the client encrypts the file, the other client who is receiving the encrypted message decrypts the message, which in turn provides confidentiality, and the client who sends the message provides a digital signature through hashing and checks to see if it is valid and if it is valid it’ll be decrypted, but if it is not valid it wont be encrypted. The digital signatures provide authentication, in which the client or server who is receiving the file message checks to see if the signature is valid and if it isn’t valid then the message including the contents of the file wont be decrypted. The design of the project was a programming project which is a software or program that was written in the Python programming langauge, it uses multiple python libraries and imports, to have this program running, you must first run the server with the command “ python3 server.py 3456 127.0.0.1”, if you try to run a client file first it will throw an exception message saying client doesn’t exist, the components of this program or software are that its a server file, which accepts multiple client connections and receives message from a client, displays the message contents after decrypting it and broadcasts the messages containing the file contents to the other clients listening or waiting in the server, but doesn’t send the message containing the file contents back to the client who sent it recently, instead it keeps it and waits for any more clients in the server, whenever a client disconnects from the server it sends a message saying client disconnected from the server and removes the client who disconnected from its list, if a new client joins the server, it adds the client to its list of clients, if it has problems accepting connections, it displays a message error accepting connection, the server accepts multiple clients at once. The client gets its messages sent to other clients why having the server broadcast the messages to all the clients except them. To run a client file, you have to use this command “ python3 client.py 3456 127.0.0.1”. The client can send or receive messages, the client first sends the message, but before doing it the message gets encrypted, then the message containing the file contents gets hashed with a digital signature, the client inputs the host name which is the folder containing all the files and sends all the files and its contents in that folder to the server and the other clients.
There are so many security protocols provided in this program, one of which is confidentiality in which the message containing all the files and its contents gets encrypted when it gets sent and gers decrypted when the client or server receives the message, the public and private keys of the program are then exchanged between the clients and server, they both use the same public and private key, which is symmetric key encryption in which it provides confidentiality, when the messages are being sent and before they are sent it goes through hashing in which a digital signature is created, in which it provides authentication and a digital signature between the clients and the server. It provides secure communications because the messages in which the file and its contents are being stored in are being encrypted first and hashed with a digital signature. The code implementation was that it was  written in the Python programming langauge, it uses multiple python libraries and imports like os, pickle, socket, sys,threading,Cryptodome,Crypto.Util ,and threading, to have this program running, you must first run the server with the command “ python3 server.py 3456 127.0.0.1”, if you try to run a client file first it will throw an exception message saying client doesn’t exist. The server file has a “PORT_NUMBER” variable in which it gets the index 1 of what command we put in the terminal in which it is “3456”, it also has a “SERVER_IP”variable  in which it gets the index 2 of what command we put in the terminal in which it is “127.0.0.1” , they variables are set equal to argv[ whatever index num], the argv is a function and attribute of the sys library, there is a variable called “HEADER_Length”, which we use to unpickle the data structure that is being sent to the server that contains the message, file name, file, file contents, digital signature. There is a socket variable in which it creates a socket for receiving messages and it binds the server ip and the port number, the ip address and the  port number for the clients must be the same as the server in order for it to connect successfully. The program uses the same public key and private key, in which in the program there are file names and the public and private key variables are then creating  using a function called RSA.import_key which opens the files in which the two public and private keys are located in and gets the contents of the two files and stores them in a variable. There is a client list which has a list of all the clients that are connected and a addresses set that stores the set of all addresses of the clients connected, there is a printInfo function in which it takes a parameter in which you would put the data structure in and it creates a default dictionary with the list being the value and it looks through the second index of the data structure in which it contains the message containing the file and the file contents and it then appends the contents of the data structure to the file_dict variable which is the default dictionary, and the default dictionary’s key which is the “newKey = key.split('.')[0]“, in which this variable gets all the text and characters before the ‘.’ to keep the name of the file as its key and the value  of it list of tuples in which each tuple contains the keyword, filename, port number, ip address, and file contents. There is an addHeader function which pickles the data structure that the server is trying to send from the original data structure  to binary format it was being set as, there is a send message function which sends the pickled message to the other clients. The receive message unpickles the data structure or any contents being sent using the .decode() function and returns the unpickled information, there is an ecnrypt_function that creates a directory that stores all the encrypted files using the os module, it appends all the encrypted files in a list, it reads through the the files, pads the text to be a multiple of 16 bytes, it then hashes the contents of the message and file and gives them a digital signature, the encrypted files are appended to the list in a form of a diction with the file name being th key and the ciphertext which is the encrypted contents of the file,and the signature, if the signature isn’t valid, the message and contents of the file won’t be encrypted or sent, there is decrypt file function, which decrypts all the files, it creates a directory in which all the decrypted files are stored in and if the signature is valid the files will be decrypred if not then then files won’t be decrypted, there is a handle_client function in which the server looks for clients currently connected and receives data from the clients, they continuously look for clients and accepts multiple clients through threading, there is broadcast function that sends the message sent from a recent client to all the other clients in the server, it looks through the list of clients and checks to see if it isn’t the recent client who sent that message and then they send it to all the clients in the list, there is a remove client function that removes the client from the server if they disconnect and prints out where the connection closed from by accessing the addresses set that stores all the address of all the clients that disconnected, there is a start server function which continuously accepts clients and appends each client connected to the client list and gets the address of the client and stores it in the addresses dictionary, then it does another thread and calls the handle client function in the thread and because of the thread function multiple clients can be accepted at once and the file can be run at multiple times, threads cause the program to have two things happening at once and the server function runs all the functions. To run the client file you have to do  “ python3 client.py 3456 127.0.0.1”, for it to run successfully both ip address and port number have to be the same. “ python3 server.py 3456 127.0.0.1”.There is an addHeader function which pickles the data structure that the server is trying to send from the original data structure  to binary format it was being set as, there is a send message function which sends the pickled message to the other clients.There is an encrypt files functions in which there is an ecnrypt_function that creates a directory that stores all the encrypted files using the os module, it appends all the encrypted files in a list, it reads through the the files, pads the text to be a multiple of 16 bytes, it then hashes the contents of the message and file and gives them a digital signature, the encrypted files are appended to the list in a form of a dictionary with the file name being th key and the ciphertext which is the encrypted contents of the file,and the signature, if the signature isn’t valid, the message and contents of the file won’t be encrypted or sent, there is decrypt file function, which decrypts all the files, it creates a directory in which all the decrypted files are stored in and if the signature is valid the files will be decrypred if not then then files won’t be decrypted, there is a receive messages function in which theres a loop in which it continually looks for messages and it unpickles all the data in the data structure and it then decrypts the files in the function and it prints all the contents of the decrypted files,the main part of the client has a port number variable which looks at the command and takes the 1 index of the command using argv and uses the same public and private key to encrypt and decrypt files like the server does, it also uses threads to recieve messages similar to what the server does, the client receives messages similar to what the server does, but sends messages differently, in which the client only sends to the server , the server sends to multiple clients.






