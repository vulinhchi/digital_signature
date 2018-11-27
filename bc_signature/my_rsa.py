from binascii import unhexlify, hexlify
from random import randrange, getrandbits
import base64
from ast import literal_eval
# https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb
def ascii_to_int(mess):
	u = hexlify(mess.encode()).decode()
	return int(u,16)

def int_to_ascii(mess):
	return unhexlify(format(mess,"x")).decode()


def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True

    if n <= 1 or n % 2 == 0:
        return False
    
    s = 0
    r = n - 1
    # print(" n = ", n)
    while r & 1 == 0:
        s += 1
        r //=2 # chia lay phan nguyen

    for _ in range(k): # 128 * 8 = 1024
        a = randrange(2, n-1) # range from 2 to n-1
        x = pow(a, r, n) # a ^ r mod n
        if x != 1 and x != n-1:
            j = 1
            while j < s and x != n-1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n-1:
                return False
    return True


def generate_prime(length):
    p = getrandbits(length)

    # apply a mask to set MSB ans LSB to 1
    p |= (1 << length - 1) | 1
    # print(" ahihi p = ", p)
    return p


def generate_prime_number(length=1024):
    #count from 4 ( because 2 and 3 is not prime)
    p = 4
    while not is_prime(p, 128):
        # print(" p = ", p)    
        p = generate_prime(length)
    return p


def generate_prime_number_2():
    p = generate_prime_number()
    q = p + 1
    while not is_prime(q,128):
        q += 1
    return p, q

# generate key pair
def pri_key():
    p, q = generate_prime_number_2()

    e = 65537

    phi = (p-1) * (q-1)
    n=p*q
    def inv(a,b):
        x2,x1,y2,y1=1,0,0,1
        n=b
        while(b!=0):
            q=a//b
            r=a%b
            x=x2-x1*q
            y=y2-q*y1
            x2=x1
            x1=x
            y2=y1
            y1=y
            a=b
            b=r
        return x2%n

    d = inv(e,phi)
    # m = pow(ascii_to_int(m),inv(e,phi),n)
    # import into public key and private key:
    pub = (e, n)
    pri = (d, n)
    # convert tuple to base64 (bytes) for storing:
    pub_bytes = base64.b64encode(str(pub).encode())
    pri_bytes = base64.b64encode(str(pri).encode())
    # convert from bytes to string >> store in blockchain, and can convert to bytes again
    pub_string = pub_bytes.decode()
    pri_string = pri_bytes.decode()
    return pub_string, pri_string
    # return n, d, e
    


# sign 
def sign(mess, pri):# pri: key get from the blockchain/DB (string)
    # convert key from string >> bytes (base64)
    pri_bytes = pri.encode()

    # bytes(of base64) >> bytes (like tuple)
    pri_tuple = base64.b64decode(pri_bytes)
    
    pri_pair = literal_eval(pri_tuple.decode())
    
    n = pri_pair[1] # int
    d = pri_pair[0]
    
    signature = pow(mess, d , n)
    return signature


def verify(mess, signature, pub): # pub: key get from the blockchain/DB (string)
    # convert key from string >> bytes (base64)
    pub_bytes = pub.encode()

    # bytes(of base64) >> bytes (like tuple)
    pub_tuple = base64.b64decode(pub_bytes)
    
    pub_pair = literal_eval(pub_tuple.decode())
    
    n = pub_pair[1] # int
    e = pub_pair[0]

    un_signature = pow(signature, e, n)
    return un_signature == mess
    
    
def encrypt(mess, pub):
    # convert key from string >> bytes (base64)
    
    pub_bytes = pub.encode()

    # bytes(of base64) >> bytes (like tuple)
    pub_tuple = base64.b64decode(pub_bytes)
    
    pub_pair = literal_eval(pub_tuple.decode())
    
    n = pub_pair[1] # int
    e = pub_pair[0]
    
    return pow(ascii_to_int(mess), e, n) #int


def decrypt(encrypt_text, pri):
    # convert key from string >> bytes (base64)
    pri_bytes = pri.encode()

    # bytes(of base64) >> bytes (like tuple)
    pri_tuple = base64.b64decode(pri_bytes)
    
    pri_pair = literal_eval(pri_tuple.decode())
    
    n = pri_pair[1] # int
    d = pri_pair[0]
    decrypt_text = pow(encrypt_text, d, n)
    return decrypt_text 

