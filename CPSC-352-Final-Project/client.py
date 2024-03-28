from os import listdir, mkdir, path
from pickle import dumps, loads
from socket import AF_INET, SOCK_STREAM, socket
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






def receive_messages(client_socket):
    
    while True:
        try:
            data = recvMsg(client_socket)
            tup = loads(data)
            directory = decrypt_files(tup[2],pubKey, privKey)

            print("Message: " , directory)

        
        except Exception as e:
            print(f"Error receiving message from server: {e}")
            break


def encrypt_files(directory, pubKey, privKey, host_name):
    encr_files  = []
    cipher_rsa_encrypt = PKCS1_OAEP.new(pubKey, hashAlgo=None, mgfunc=None, randfunc=None)
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
            outFile = open(("encryptedfiles/encrypted" + i), "wb")
            outFile.write(cipherText)
            outfile2 = open(("encryptedfiles/encrypted" + i), "rb")
            lines2 = str(outfile2.read())
            encr_files.append({str(i) : (cipherText,signature) })
        
        except ValueError:    
            print("The signature is not valid!")

    return encr_files



def decrypt_files(directory, pubKey, privKey):
    dec_files = []
    cipher_rsa_decrypt = PKCS1_OAEP.new(privKey, hashAlgo=None, mgfunc=None, randfunc=None)
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
                    outFile = open(("decryptedfiles/decrypted" + key), "wb")
                    outFile.write(plainText)
                    outFile.flush()
                    dec_files.append({key : (plainText,signature)})
            except ValueError:    
                    print("The signature is not valid! so it won't be decrypted")    
            
    return dec_files


PORT_NUMBER = int(argv[1])
SERVER_IP = argv[2]  
HEADER_LENGTH = 5
PUBLIC_KEY_FILE_NAME = "public-key.pem"
PRIVATE_KEY_FILE_NAME = "private-key.pem"
pubKey = RSA.import_key(open(PUBLIC_KEY_FILE_NAME).read())
privKey = RSA.import_key(open(PRIVATE_KEY_FILE_NAME).read())

host_name = input("Enter a host name: ")
directory = listdir(host_name)
print(directory)

enc_files = encrypt_files(directory, pubKey, privKey,host_name)

data = (PORT_NUMBER, SERVER_IP, enc_files)
info = dumps(data)

client_socket = socket(AF_INET, SOCK_STREAM)
try:
    client_socket.connect((SERVER_IP, PORT_NUMBER))
    print("Connected to server.")
    sendMsg(info, client_socket)

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()
except Exception as e:
    print(f"Error connecting to server: {e}")







"""def encrypt_files(directory, pubKey, privKey, host_name):
    encr_files  = []
    cipher_rsa_encrypt = PKCS1_OAEP.new(pubKey, hashAlgo=None, mgfunc=None, randfunc=None)
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
            outFile = open(("encryptedfiles/encrypted" + i), "wb")
            outFile.write(cipherText)
            outfile2 = open(("encryptedfiles/encrypted" + i), "rb")
            lines2 = str(outfile2.read())
            encr_files.append({str(i) : cipherText})
        
        except ValueError:    
            print("The signature is not valid!")

    return encr_files

def receive_messages(client_socket):
    
    while True:
        try:
            print("work fine")
            fgf = b''
            while True:
                print("Its still running")
                inf = client_socket.recv(4096)
                print("Message, ", inf)
                if not inf:
                    break

                fgf += inf
            client_socket.close()        
            info = loads(fgf)        
            print(f"Received message from server: {info}")
            
        
        except Exception as e:
            print(f"Error receiving message from server: {e}")
            break






PORT_NUMBER = int(argv[1])
SERVER_IP = argv[2]  
PUBLIC_KEY_FILE_NAME = "public-key.pem"
PRIVATE_KEY_FILE_NAME = "private-key.pem"
pubKey = RSA.import_key(open(PUBLIC_KEY_FILE_NAME).read())
privKey = RSA.import_key(open(PRIVATE_KEY_FILE_NAME).read())

host_name = input("Enter a host name: ")
directory = listdir(host_name)
print(directory)

encr_files = encrypt_files(directory, pubKey, privKey, host_name)

data = (PORT_NUMBER, SERVER_IP, encr_files)
info = dumps(data)

client_socket = socket(AF_INET, SOCK_STREAM)
try:
    client_socket.connect((SERVER_IP, PORT_NUMBER))
    print("Connected to server.")
    client_socket.send(info)

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()
except Exception as e:
    print(f"Error connecting to server: {e}")"""






"""finally:
    client_socket.close()"""













"""
PORT_NUMBER = int(argv[1])
SERVER_IP = argv[2]  
PUBLIC_KEY_FILE_NAME = "public-key.pem"
PRIVATE_KEY_FILE_NAME = "private-key.pem"
pubKey = RSA.import_key(open(PUBLIC_KEY_FILE_NAME).read())
privKey = RSA.import_key(open(PRIVATE_KEY_FILE_NAME).read())



#ENCRYPTION_KEY = argv[3].encode() #arg 3 is encryption key

key = b'hello12345678s0d1111111111111111'
dir = input("Enter a host name: ")
directroy = listdir(dir)
print(directroy)
encr_files  = []

cipher_rsa_encrypt = PKCS1_OAEP.new(pubKey, hashAlgo=None, mgfunc=None, randfunc=None)
for i in directroy:
    file = open((dir + "/" + i), 'rb')
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
        outFile = open(("encryptedfiles/encrypted" + i), "wb")
        outFile.write(cipherText)
        #encr_files.append(i)
        outfile2 = open(("encryptedfiles/encrypted" + i), "rb")
        lines2 = str(outfile2.read())
        encr_files.append({str(i) : cipherText})
    
    except ValueError:    
        print("The signature is not valid!")


    



data = (PORT_NUMBER, SERVER_IP, encr_files)
info = dumps(data)


cliSock = socket(AF_INET, SOCK_STREAM)
cliSock.connect((SERVER_IP, PORT_NUMBER))




cliSock.send(info)"""























"""PORT_NUMBER = int(argv[1])
SERVER_IP = argv[2]  
PUBLIC_KEY_FILE_NAME = "public-key.pem"
PRIVATE_KEY_FILE_NAME = "private-key.pem"
pubKey = RSA.import_key(open(PUBLIC_KEY_FILE_NAME).read())
privKey = RSA.import_key(open(PRIVATE_KEY_FILE_NAME).read())
    #ENCRYPTION_KEY = argv[3].encode() #arg 3 is encryption key
username = input("Enter a username: ")
password = input("Enter a password: ")
dir = input("Enter a directory name: ")
directroy = listdir(dir)
print(directroy)
encr_files  = []

correct_password = open("client1password.txt", "r").read()

cipher_rsa_encrypt = PKCS1_OAEP.new(pubKey, hashAlgo=None, mgfunc=None, randfunc=None)
for i in directroy:
    file = open((dir + "/" + i), 'rb')
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
    outFile = open(("encryptedfiles/encrypted" + i), "wb")
    outFile.write(cipherText)
    #encr_files.append(i)
    outfile2 = open(("encryptedfiles/encrypted" + i), "rb")
    lines2 = str(outfile2.read())
    encr_files.append({str(i) : (cipherText, signature)})

except ValueError:    
    print("The signature is not valid!, so it won't be sent")

data = (PORT_NUMBER, SERVER_IP, encr_files, username)
info = dumps(data)


cliSock = socket(AF_INET, SOCK_STREAM)
cliSock.connect((SERVER_IP, PORT_NUMBER))
cliSock.send(info)"""

"""def send_data_to_server(PORT_NUMBER,SERVER_IP,encr_files,username):
    PUBLIC_KEY_FILE_NAME = "public-key.pem"
    PRIVATE_KEY_FILE_NAME = "private-key.pem"
    pubKey = RSA.import_key(open(PUBLIC_KEY_FILE_NAME).read())
    privKey = RSA.import_key(open(PRIVATE_KEY_FILE_NAME).read())
    

    data = (PORT_NUMBER, SERVER_IP, encr_files, username)
    info = dumps(data)
    cliSock = socket(AF_INET, SOCK_STREAM)
    cliSock.connect((SERVER_IP, PORT_NUMBER))
    while True:
        cliSock.send(info)
        cliSock.close()




def send_data_to_client(PORT_NUMBER,SERVER_IP,encr_files,username):
    PUBLIC_KEY_FILE_NAME = "public-key.pem"
    PRIVATE_KEY_FILE_NAME = "private-key.pem"
    pubKey = RSA.import_key(open(PUBLIC_KEY_FILE_NAME).read())
    privKey = RSA.import_key(open(PRIVATE_KEY_FILE_NAME).read())
    

    data = (PORT_NUMBER, SERVER_IP, encr_files, username)
    info = dumps(data)
    cliSock = socket(AF_INET, SOCK_STREAM)
    cliSock.connect((SERVER_IP, PORT_NUMBER))
    while True:
        cliSock.send(info)
        cliSock.close()





SERVER_PORT_NUMBER = int(argv[1])
CLIENT_PORT_NUMBER = int(argv[2])

SERVER_IP = argv[3]  
PUBLIC_KEY_FILE_NAME = "public-key.pem"
PRIVATE_KEY_FILE_NAME = "private-key.pem"
pubKey = RSA.import_key(open(PUBLIC_KEY_FILE_NAME).read())
privKey = RSA.import_key(open(PRIVATE_KEY_FILE_NAME).read())
    #ENCRYPTION_KEY = argv[3].encode() #arg 3 is encryption key
username = input("Enter a username: ")
password = input("Enter a password: ")
dir = input("Enter a directory name: ")
directroy = listdir(dir)
print(directroy)
encr_files  = []
correct_password = open("client1password.txt", "r").read()

cipher_rsa_encrypt = PKCS1_OAEP.new(pubKey, hashAlgo=None, mgfunc=None, randfunc=None)
for i in directroy:
    file = open((dir + "/" + i), 'rb')
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
    outFile = open(("encryptedfiles/encrypted" + i), "wb")
    outFile.write(cipherText)
    #encr_files.append(i)
    outfile2 = open(("encryptedfiles/encrypted" + i), "rb")
    lines2 = str(outfile2.read())
    encr_files.append({str(i) : (cipherText, signature)})

except ValueError:    
    print("The signature is not valid!, so it won't be sent")






server_thread = threading.Thread(target=send_data_to_server, args=(SERVER_PORT_NUMBER, 
                SERVER_IP, encr_files,username))



client_thread = threading.Thread(target=send_data_to_client, args=(CLIENT_PORT_NUMBER, 
                SERVER_IP, encr_files,username))



server_thread.start()
client_thread.start()
"""








