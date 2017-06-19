import hashlib
import hmac
import os
import struct
import hexdump

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from twofish import CBCMode
from twofish import Twofish

KEY_STORE_PEM = "myRSAkey.pem"
KEY_SEED = "\x6D\x61\x73\x74\x65\x72\x20\x73\x65\x63\x72\x65\x74"

KEY_STORE = {}


### random data

def getRandomBytes(bytes):
    return os.urandom(bytes)


def createKeyData():
    (prandom, masterkey) = (getRandomBytes(28), getRandomBytes(28))
    KEY_STORE['prandom'] = prandom
    KEY_STORE['masterkey'] = masterkey  # not needed?
    return (prandom, masterkey)


### key hash functions

def deriveKeys(secret, seed_prefix, seed):
    return evenHalveString(multiHashXOR(secret, seed_prefix + seed, 32))


def evenHalveString(string):
    l = len(string)
    first = string[:l / 2 + l % 2]
    second = string[l / 2:l]
    return (first, second)


def getHmac(secret, data, hash):
    return hmac.new(secret, data, hash).digest()


def Khmac(secret, seed, bytes, hash):
    nu_seed = seed
    output = ''
    while len(output) < bytes:
        nu_seed = getHmac(secret, nu_seed, hash)
        output += getHmac(secret, nu_seed + seed, hash)
    return output[:bytes]


def sha1Khmac(secret, seed, bytes):
    return Khmac(secret, seed, bytes, hashlib.sha1)


def md5Khmac(secret, seed, bytes):
    return Khmac(secret, seed, bytes, hashlib.md5)


def stringXOR(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


def multiHashXOR(secret, seed, bytes):
    (r1, r2) = evenHalveString(secret)
    m1 = md5Khmac(r1, seed, bytes)
    s1 = sha1Khmac(r2, seed, bytes)
    return stringXOR(m1, s1)


def incrementNonce(string):
    nonce = long(hd(string[::-1]), 16)
    nonce += 1
    bstring = longToBytes(nonce, len(string))
    return bstring


def longToBytes(val, num_bytes):
    return ''.join([chr((val & (0xff << pos * 8)) >> pos * 8) for pos in range(num_bytes)])


### public key routines

def getRSAkey():
    if os.path.exists(KEY_STORE_PEM):
        with open(KEY_STORE_PEM, mode='rb') as pemfile:
            key = RSA.importKey(pemfile.read())
            print "Loaded pre-generated RSA key"
    else:
        print "Generating RSA key - please wait this may take some minutes!"
        key = RSA.generate(2048, randfunc=os.urandom)
        with open(KEY_STORE_PEM, mode='wb') as pemfile:
            pemfile.write(key.exportKey('PEM'))
        print "Key Generated and saved"

    return key


def publicKeyFromString(string):
    key = RSA.construct((long(hd(string), 16), long(65537)))
    return key


def encryptWithPeerRSAkey(data, pubkey):
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(data)


def hd(s):
    return hexdump.dump(s).lower().replace(" ", "")


### symmetric ciphers

def blockCipherZeroPad(input):
    modulus = len(input) % 16
    if modulus == 0:
        return input
    return input + ('\00' * (16 - modulus))


def produceCCMPrimitive(header_byte, nonce, number):
    s = struct.Struct(">B13sH")
    prim = s.pack(header_byte, nonce, number)
    return prim


def produceIV(nonce, payload_size):
    return produceCCMPrimitive(0x59, nonce, payload_size)


def produceCTRblock(nonce, counter):
    return produceCCMPrimitive(0x01, nonce, counter)


def CTRmodeEncryptData(plain, nonce, key):
    if (key is None): return None
    padded = blockCipherZeroPad(plain)
    stream = ''
    for i in range(len(padded) >> 4):
        stream += Twofish(key).encrypt(produceCTRblock(nonce, i + 1))
    return stringXOR(padded, stream)[:len(plain)]


def produceHeaderHeader(header):
    s = struct.Struct(">H" + str(len(header)) + "s")
    return s.pack(len(header), header)


def produceCCMtag(nonce, payload, header, key=None):
    if (key == None):
        raise AttributeError("CCMtag key undefined")
    iv = Twofish(key).encrypt(produceIV(nonce, len(payload)))
    processed_header = blockCipherZeroPad(produceHeaderHeader(header))
    result = (CBCMode(Twofish(key), iv).encrypt(processed_header + blockCipherZeroPad(payload)))
    result = result[len(result) - 16:len(result) - 8]  # mac
    ctr = Twofish(key).encrypt(produceCTRblock(nonce, 0))
    final = stringXOR(result, ctr)
    return final


### self tests

assert (hd(produceCCMtag(key="\x9e\x89\xef\x30\xb5\x6a\x5d\x6a\x99\x17\x2b\x31\x8c\xb2\x6c\x6c",
                         nonce="\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xab",
                         payload='\x67\xef\x3a\xfc\x48\x4e\x69\x0a\x30\x3c\x45\xd1\xec\xe5\x49\x53' * 5,
                         header='\xbb\xe1\xe7\xf1\x40\x7e\x23\x5c\xe6\x8b\x9a\xd7\x4a\x14\x29\xfe' * 5)) == "8062ec3ab19db5cb")

if __name__ == "__main__":
    print "Running cypto test parameters"
    print getRSAkey().exportKey('PEM')
    print "Tag Result: " + hd(produceCCMtag(key="\x9e\x89\xef\x30\xb5\x6a\x5d\x6a\x99\x17\x2b\x31\x8c\xb2\x6c\x6c",
                                            nonce="\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xab",
                                            payload='\x67\xef\x3a\xfc\x48\x4e\x69\x0a\x30\x3c\x45\xd1\xec\xe5\x49\x53' * 5,
                                            header='\xbb\xe1\xe7\xf1\x40\x7e\x23\x5c\xe6\x8b\x9a\xd7\x4a\x14\x29\xfe' * 5))
