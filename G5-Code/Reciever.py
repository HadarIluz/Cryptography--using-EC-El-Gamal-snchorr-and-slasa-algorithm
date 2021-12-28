from pureSalsa20 import Salsa20
from ecc.cipher import ElGamal
from ecc.curve import Curve25519
from ecc.key import gen_keypair
import schnorr

# This function get public key , big prime number , generatorNumber , and hash function
# This function create and return verify object using the SchnorrVerifier
def CreateVerification(publicKey, primeNumer, generatorNumber):
    return schnorr.SchnorrVerifier(keys=publicKey, p=primeNumer, g=generatorNumber, hash_func=schnorr.sha256_hash)

#This function create and return private and public keys using Curve25519
def CreateKeys():
    return gen_keypair(Curve25519)
    