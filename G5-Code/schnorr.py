import struct
from hashlib import sha256
from random import randint
from typing import Callable, Union, Tuple, Sequence

from signature import Signature, Signer, Verifier


def sha256_hash(r: str, message: str) -> int:
    """
    An hash function, using SHA-256.

    :param r: r paramter from schnorr.
    :pa ram message: message to hash
    :return:
    """
    hasho = sha256()
    hasho.update(r.encode())
    hasho.update(message.encode())
    return int(hasho.hexdigest(), 16)


class SchnorrSignature(Signature):
    """
    Schnorr signature.

    Composed of two parameters: e, s that can be used
    by the verifier to indicate correctness.
    """
    _FORMAT = '>ll'

    def __init__(self, data: Union[Tuple[int, int], bytes]):
        """
        Creates a new signature.

        :param data: either:
            a tuple of 2 ints: e, s
            bytes created from `pack()` which indicate a serialized signature.
        """
        if type(data) == tuple:
            # if tuple, then simply open it for e, s
            self._e, self._s = data
        elif type(data) == bytes:
            # if bytes, we need to unpack the serialized data
            self._e, self._s = 0, 0
            self.unpack(data)
        else:
            raise ValueError('Expected packed bytes or tuple of values')

    @property
    def e(self):
        return self._e

    @property
    def s(self):
        return self._s

    def pack(self) -> bytes:
        """
        Serializes the signature data into binary data. Used for sending
        the signature information.

        :return: serialized signature.
        """
        return struct.pack(self._FORMAT, self._e, self._s)

    def unpack(self, data: bytes):
        """
        Deserializes the signature data (which was previously serialized with pack()).

        :param data: serialized data to deserialize.
        """
        self._e, self._s = struct.unpack(self._FORMAT, data)

    def __repr__(self):
        return f"{self.e}, {self.s}"


class SchnorrSigner(Signer):
    """
    A Schnorr signer. Produces signatures for data.
    """

    def __init__(self, key: int, p: int, g: int, hash_func: Callable[[str, str], int]):
        """

        :param key: key for signing (must be private)
        :param p: prime number
        :param g: generator.
        :param hash_func: function for hashing
        """
        self._key = key
        self._p = p
        self._g = g
        self._hash_func = hash_func

    def sign(self, data: str) -> SchnorrSignature:
        """
        Signs the given data using the secret key.

        :param data: data to sign
        :return: signature.
        """
        k = randint(1, self._p - 1)   #random value
        r = pow(self._g, k, self._p)  # g^k mod p
        e = self._hash_func(str(r), data) % self._p #hush func
        s = (k - (self._key * e)) % (self._p - 1)  

        return SchnorrSignature((e, s))


class SchnorrVerifier(Verifier):
    """
    A Schnorr verifier. Verifies signatures and data.
    """

    def __init__(self, keys: Union[int, Sequence[int]], p: int, g: int, hash_func: Callable[[str, str], int]):
        """

        :param keys: either
            - trusted public key
            - list of trusted public keys
        :param p: prime number
        :param g: generator
        :param hash_func: function for hashing
        """
        if type(keys) == int:
            self._keys = [keys]
        else:
            self._keys = keys

        self._p = p
        self._g = g
        self._hash_func = hash_func

    def verify(self, data: str, signature: SchnorrSignature) -> bool:
        """
        Verifies the signature on the data is valid and produced from an 
        accepted source.
        
        :param data: data to verify the signature for 
        :param signature: signature of the message to verify.
        :return: True if the signature was verified, False otherwise.
        """
        # if might have several acceptable sources, each with a different public key,
        # so we check that we match any one of them.
        return any([self._verify_one(key, data, signature) for key in self._keys])

    def _verify_one(self, key: int, data: str, signature: SchnorrSignature) -> bool:
        """
        Verifies the signature on the data is valid and produced from an
        accepted source.

        :param key: public key of the source
        :param data: data to verify the signature for
        :param signature: signature of the message to verify.
        :return: True if the signature was verified, False otherwise.
        """
        rv = (pow(self._g, signature.s, self._p) * pow(key, signature.e, self._p)) % self._p
        ev = self._hash_func(str(rv), data) % self._p

        return signature.e == ev
