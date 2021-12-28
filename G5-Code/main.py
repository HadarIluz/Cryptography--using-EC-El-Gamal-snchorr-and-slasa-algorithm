
from os import urandom
from pureSalsa20 import Salsa20
import Reciever
from ecc.curve import Curve25519
from ecc.cipher import ElGamal
from binascii import hexlify, unhexlify
import schnorr
from random import randint

# This is our database useres and passwords
users = ['Tal','Sharon','Haim','Hadar','Bob','Alice']
passwords = ['111','222','333','444','bob1996','alice1995']

# This is our generator and prime numberse
generatorNumber = 2 
primeNumber = 6700417

# This while waiting for correcr inputs of username and passow
while(True):
    username = input("Please enter user name: ")
    password = input("Please enter user password: ")
    if(username in users):
        index = users.index(username)
        if(passwords[index] == password):
            break
        else:
            print("You entered wrong user password\n")
    else:
        print("You entered wrong user name\n")



# Create public and private keys for the reciever
recieverPrivateKey,recieverPublicKey = Reciever.CreateKeys()  

 
################# Sender encryption #################

# Create 4x2 bytes random nonce and convert it to hex
nonce = hexlify(urandom(4))

#Create 8x2 bytes random salsaKey and convert it to hex
salsaKey = hexlify(urandom(8))      

# Encrypt message with salsa20 
originalMsg = input("Please enter the amount of the money you want to transfer: ")
byteMsg = str.encode(originalMsg) # this convert the message to byte string
print("\nStarting the encryption process...\n")

#create new salsa20 object with our salsa key and nonce and encrypt the message
salasaObject = Salsa20(salsaKey,nonce)
encryptedText = salasaObject.encryptBytes(byteMsg) 

print("The original message:",originalMsg)
print("\nThe encrypted message after using salsa20:\n",encryptedText)

# Encrypt the salsaKey with El-Gamal
print("\nThe original key of salsa20:\n",salsaKey)
elGamalObj = ElGamal(Curve25519) 
C1, C2 = elGamalObj.encrypt(salsaKey, recieverPublicKey)
print("\nThe encrypted key using El-Gamal:\n",C1, C2)

# Create sender public and private keys for Schnorr signature:
senderPrivateKey = randint(1000, 1000000) 
senderPublicKey = pow(generatorNumber, senderPrivateKey, primeNumber) 

# Create the Schnorr signature with the keys:
signatureObj = schnorr.SchnorrSigner(key=senderPrivateKey, p=primeNumber, g=generatorNumber, hash_func=schnorr.sha256_hash)
signature = signatureObj.sign(str(originalMsg))

print("\n" + username + " sending encrypted message,encrypted key and the signature to the reciever...\n")

################# End sender encryption #################


print("\nReciever recived the encrypted message,encrypted key and the signature from " +username+"\n")
print("\nStarting the decryption process...\n")

################# Reciever decryption #################

# decrypt the sls20 encrypted key
decrypytedElGamalKey = elGamalObj.decrypt(recieverPrivateKey, C1, C2)
print("\nthe decrypt key:\n",decrypytedElGamalKey)
    
#create new salsa20 object with our decrypted salsa key and nonce and decrypt the message
salasaObject = Salsa20(decrypytedElGamalKey,nonce)
decryptedText = salasaObject.decryptBytes(encryptedText)
print ("\nThe decrypt message is:",decryptedText.decode())

# Reciever compares the signature he got to the signature that sender sent her.
print("Starting verfication process...\n")
SnchorrVerificationObj = Reciever.CreateVerification(senderPublicKey, primeNumber, generatorNumber)
isVerified = SnchorrVerificationObj.verify(decryptedText.decode(), signature)
if(isVerified):
     print("The verfication process completed successfully\n The message is from " + username)
else:
    print("The verfication process failed\n The message is NOT from " + username)

################# End reciever decryption #################











