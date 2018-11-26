from binascii import unhexlify, hexlify
from random import randrange, getrandbits
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
    return n, d , e


# sign 
def sign(mess, private_key, n):
    # print("private_key = ", private_key)
    signature = pow(ascii_to_int(mess), private_key , n)
    return signature


def verify(mess, signature, public_key , n):
    un_signature = pow(signature, public_key, n)
    return int_to_ascii(un_signature) == mess
    
    


m = "ahihi"

# # encode:
# n , d , e = pri_key()

n = 29836544274755731529614329723299643005741263129971387634017504984087265739860673412590878160081621083774617572071140066025917501107515486138374688734587304780794295862131842387670982670129358346142736155771354265797094785772989279198007053165889986511435609732955958687949462109487856227318881388796889800110878579481935731811776782537356920464629798298196959484957966765043912179999164036797848690313670886484801698580710573804746118085551657547703163915686748194146006402391514242882145414883894616978253213424964801486525875790323683660844490168555309460407290570880973280203416983669097294318418367434327424406213
d = 17292238906084302770791172709768380308635891137307219074765199685835278004747363447067142608822195303798027057081924914595761546066599946747545444591693693600392293509488590710757387960381516060569442412754067917020477764438644609789552495542975713835907331194391964521482283584916569923589011883221268371722818854712181021397863751313298457630365887419017441217790320086112754992424117112271880186886955486257510685388180834719893392072141713216588858910666552940386320255906053895153784419358365365380687233793141080364355988069643983391982324404266848674595130526589611224637687964505101693710946274240173619144053
e = 65537 # public key

pub_wallet = 0x26ADdBcD2c9A2186C75b676c857ea10D1d4e5e2D
pri_wallet = 0xad14ce7e7a577086dc3905576522ceca385391ac33cfff6ec7b02423854d17c1

# c = pow(ascii_to_int(m), e , n)
# print("encode: ", c)

# # decode:
# mess = pow(c,d,n)
# print(unhexlify(format(mess,"x")).decode())


mess = "hello"
# a = pow(ascii_to_int(mess), d , n)
a = sign(mess, d, n)
print("signature: ",a)
print(verify(mess,a,e,n))

# 
b = sign(mess, pri_wallet , n)
print(b)
print(int_to_ascii(b))
un_signature = pow(b, pub_wallet, n)
print(" ssd")
print(un_signature)
print(int_to_ascii(un_signature))


