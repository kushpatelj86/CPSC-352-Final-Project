from collections import defaultdict
from os import listdir, mkdir, path
from pickle import dumps, loads
from socket import AF_INET, SO_REUSEADDR, SOCK_STREAM, SOL_SOCKET, socket
from sys import argv
import threading
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import binascii
import Cryptodome.Signature.pkcs1_15 




PORT_NUMBER = int(argv[1])
SERVER_IP = argv[2]
HEADER_LENGTH = 5
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
server_socket.bind((SERVER_IP, PORT_NUMBER))
server_socket.listen(5)
PUBLIC_KEY_FILE_NAME = "public-key.pem"
PRIVATE_KEY_FILE_NAME = "private-key.pem"
pubKey = RSA.import_key(open(PUBLIC_KEY_FILE_NAME).read())
privKey = RSA.import_key(open(PRIVATE_KEY_FILE_NAME).read())


clients = []
addresses = {}

def printInfo(tup):
    file_dict = defaultdict(list)
    print(tup)
    for i in tup[2]:
        for key,value in i.items():
            newKey = key.split('.')[0]
            file_dict[newKey].append((key,value[0],value[1], tup[0], tup[1]))


        
    for key, value in file_dict.items():
            for i in value:
                print("Keyword: " + key + "    File name: " + i[0]    +"      Port Number: " +  str(tup[0]) + "   Domain Name: " +  tup[1])
                print("File contents: ", i[1])
                #print("Digital Signature: ", i[2])

        

  






def addHeader(data):

        # The lenght of the data
        dataLen = len(data)

        # Conver the length to bytes
        dataLenBytes = str(dataLen).encode()

        # Prepend 0's until the length is right
        while len(dataLenBytes) < HEADER_LENGTH:
            dataLenBytes =  b'0' + dataLenBytes


        return dataLenBytes + data


def sendMsg(msg, socket):
    
    headerAndData = addHeader(msg)

    socket.sendall(headerAndData)




def recvMsg(sock):

    length = int(sock.recv(HEADER_LENGTH).decode())

    data = sock.recv(length)

    return data





def encrypt_files(directory, pubKey, privKey, host_name):
    encr_files  = []
    cipher_rsa_encrypt = PKCS1_OAEP.new(pubKey, hashAlgo=None, mgfunc=None, randfunc=None)
    encrypted_file_directory = input("What do you want to name your encrypted file directory: ")
    mkdir(encrypted_file_directory)

    for i in directory:
        file = open((host_name + "/" + i), 'rb')
        lines = str(file.read())
        paddedMsg = pad(lines.encode(), 16) 	# Pads the text to be a multiple of 16 bytes
        cipherText = cipher_rsa_encrypt.encrypt(paddedMsg)
        hash = SHA256.new(cipherText)
        sig1 = Cryptodome.Signature.pkcs1_15.new(privKey)
        signature = sig1.sign(hash)
        verifier = Cryptodome.Signature.pkcs1_15.new(pubKey)
        try:
            verifier.verify(hash, signature)
            print("The signature is valid! and it will be sent")
            outFile = open((encrypted_file_directory+"/encrypted" + i), "wb")
            outFile.write(cipherText)
            outfile2 = open((encrypted_file_directory+"/encrypted" + i), "rb")
            lines2 = str(outfile2.read())
            encr_files.append({str(i) : (cipherText,signature) })
        
        except ValueError:    
            print("The signature is not valid!")

    return encr_files





def decrypt_files(directory, pubKey, privKey):
    dec_files = []
    cipher_rsa_decrypt = PKCS1_OAEP.new(privKey, hashAlgo=None, mgfunc=None, randfunc=None)
    decrypted_file_directory = input("What do you want to name your decrypted file directory: ")
    mkdir(decrypted_file_directory)
    for i in directory:
        print(type(i))
        for key,values in i.items():
            print(type(key))
            print(type(values))
            print(type(i[key][0]))
            print(type(i[key][1]))

            hash = SHA256.new(values[0])
            sig1 = Cryptodome.Signature.pkcs1_15.new(privKey)
            signature = sig1.sign(hash)
            verifier = Cryptodome.Signature.pkcs1_15.new(pubKey)
            try:
                    verifier.verify(hash, signature)
                    print("The signature is valid! and it will be decrypted")
                    plainText = cipher_rsa_decrypt.decrypt(values[0])
                    print("Decrypted text: ", plainText)    
                    outFile = open((decrypted_file_directory+"/decrypted" + key), "wb")
                    outFile.write(plainText)
                    outFile.flush()
                    dec_files.append({key : (plainText,signature)})
            except ValueError:    
                    print("The signature is not valid! so it won't be decrypted")    
            
    return dec_files




def handle_client(client_socket, client_address):
    while True:
        try:
            
            data = recvMsg(client_socket)
            tup = loads(data)
            directory = tup[2]
            print(directory)
            files = decrypt_files(directory, pubKey, privKey)

            newTup = (tup[0],tup[1],files)



            print(f"Received message from {client_address}: {newTup}")

            printInfo(newTup)    

            broadcast(tup, client_socket)
            print("Any more clients")
                
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
            remove_client(client_socket)
            break



def broadcast(message, client_socket):
    for client in clients:
        if client_socket != client:
             

            try:
                newMsg = (message[0], message[1],message[2])
                info = dumps(newMsg)
                sendMsg(info, client)
            except Exception as e:
                print(f"Error broadcasting message to client: {e}")
                client.close()
                remove_client(client)

def remove_client(client_socket):
    if client_socket in clients:
        clients.remove(client_socket)
        client_address = addresses[client_socket]
        print(f"Connection closed from {client_address}")
        del addresses[client_socket]
        client_socket.close()

def start_server():
    print(f"Server is listening on {SERVER_IP}:{PORT_NUMBER}")
    while True:
        try:
            client_socket, client_address = server_socket.accept()
            print(f"Connection established from {client_address}")
            clients.append(client_socket)
            print(clients)
            addresses[client_socket] = client_address
            print(addresses[client_socket])

            client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_handler.start()
        except Exception as e:
            print(f"Error accepting connection: {e}")

start_server()

























