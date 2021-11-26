# Cryptography

## Mini RSA ![p](https://img.shields.io/badge/Points-20-success) ![c](https://img.shields.io/badge/Crypto-orange)

## Mind your Ps and Qs ![p](https://img.shields.io/badge/Points-20-success) ![c](https://img.shields.io/badge/Crypto-orange)
> Decrypt my super sick RSA:  
> c: 964354128913912393938480857590969826308054462950561875638492039363373779803642185  
> n: 1584586296183412107468474423529992275940096154074798537916936609523894209759157543  
> e: 65537

We can easily see that, as hinted, the modulus N is too small. In this way we can simply factor it (factordb) and get P and Q.  
Now we can calculate `PHI = (P-1)*(Q-1)` and `D = E^(-1) mod PHI`, to decrypt the given C we just calculate `M = C^D mod N` and convert it into text.

Flag: **picoCTF{sma11_N_n0_g0od_73918962}**

## Easy Peasy ![p](https://img.shields.io/badge/Points-40-success) ![c](https://img.shields.io/badge/Crypto-orange) 

We are given a Python script granting an OTP encryption, so let's analyze it and find some weaknesses.  
Here is how the program works: it first encrypts the flag, then a loop is performed to get our input and encrypt it using a key of 50000 lenght, leading to different encryption of the same characters in different inputs. *start* is where the needed key part sholud start, and *stop* is where it should end.  
The most important rule of an One Time Pad is that the key is never reused in part or in whole. We notice this in the encryption part:
```python
if stop >= KEY_LEN:
   stop = stop % KEY_LEN
   key = kf[start:] + kf[:stop]
```
This means that if we reach the end of the key, we will restart and reuse the key from the beginning! Knowing that, we can trick the program in our favour.

Let's send 49968 characters (added to 32 of the flag we reach 50000), and then 32 chosen characters: we will obtain the characters encrypted with the SAME key as the flag.  
**Note:** at first I sent 32 'A's to encrypt, but I soon realized that sending 32 null bytes would lead to a quicker solution.

Let's first recover the encrypted flag by just connecting with `nc mercury.picoctf.net 41934`, so `0345376e1e5406691d5c076c4050046e4000036a1a005c6b1904531d3941055d`.  
Let's send this `python -c "print('A'*49968);print(b'\x00'*32)" | nc mercury.picoctf.net 41934` obtaining `6227515c7863625c7838615c7862345c7830345c7866385c7830307b5c786464`, our key.  

Now we just need to XOR the two values and obtain the flag:
```python
>>> ef=0x0345376e1e5406691d5c076c4050046e4000036a1a005c6b1904531d3941055d
>>> k=0x6227515c7863625c7838615c7862345c7830345c7866385c7830307b5c786464
>>> '{:x}'.format(ef^k)
'6162663266376435656466303832303238303736626664376134636665396139'
```
Translated into ASCII text, this will show the flag to submit and get the points.

Flag: **picoCTF{abf2f7d5edf082028076bfd7a4cfe9a9}**

## New Caesar ![p](https://img.shields.io/badge/Points-60-success) ![c](https://img.shields.io/badge/Crypto-orange)

What we have here is a ciphertext (_ihjghbjgjhfbhbfcfjflfjiifdfgffihfeigidfligigffihfjfhfhfhigfjfffjfeihihfdieieih_) and a python script: 
```python
import string

LOWERCASE_OFFSET = ord("a") # 97
ALPHABET = string.ascii_lowercase[:16] # abcdefghijklmnop

def b16_encode(plain):
	enc = ""
	for c in plain:
		binary = "{0:08b}".format(ord(c)) # just the binary value of the char, 'a' = 01100001
		enc += ALPHABET[int(binary[:4], 2)] # MSBs of the binary converted in decimal, used as index of alphabet
		enc += ALPHABET[int(binary[4:], 2)] # same with LSBs
	return enc

def shift(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 + t2) % len(ALPHABET)]

flag = "redacted"
key = "redacted"
assert all([k in ALPHABET for k in key]) # every char in the key is in the alphabet
assert len(key) == 1 # key of lenght 1 ???

b16 = b16_encode(flag)
enc = ""
for i, c in enumerate(b16):
	enc += shift(c, key[i % len(key)])
print(enc)
```

I added some comments in order to better understand the behaviour, and the most important thing we can notice is that **the key lenght is only 1**! This means that should be easy to invert the process and rewrite this script in order to decrypt the given ciphertext, bruteforcing the key on an alphabet of 16 characters.

We can divide the encryption algorithm in 2 parts: encode and shift. Now to decrypt we will need to first shift back the characters and then to decode.  
The switching part is kinda easy, just make t1 - t2 and we are done. The decoding part is more complex but we just reverse the whole process, so we take pairs of ciphertext letters, take their index in the ALPHABET and print them as binary (`zfill(4)` to make sure we have 4 bits).  
After that we concatenate them and convert this into a character, and by concatenating everything we can print a flag candidate. Of course we will do this for every possible key, and eventually we will find a suitable flag.

The final script is:
```python
import string
enc = "ihjghbjgjhfbhbfcfjflfjiifdfgffihfeigidfligigffihfjfhfhfhigfjfffjfeihihfdieieih"

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_decode(ctx):
	flag = ""
	for c in range(0, len(ctx) ,2):
	    first = "{0:b}".format(ALPHABET.index(ctx[c])).zfill(4)
	    second = "{0:b}".format(ALPHABET.index(ctx[c+1])).zfill(4)
	    res = first + second
	    flag += chr(int(res,2))
	return flag

def shiftBack(c, k):
	t1 = ord(c) - LOWERCASE_OFFSET
	t2 = ord(k) - LOWERCASE_OFFSET
	return ALPHABET[(t1 - t2) % len(ALPHABET)]

for key in ALPHABET:
    b16 = ""
    for i, c in enumerate(enc):
	    b16 += shiftBack(c, key[i % len(key)])
    flag = b16_decode(b16)
    print(flag)
```

Flag: **picoCTF{et_tu?\_0797f143e2da9dd3e7555d7372ee1bbe}**

## Mini RSA ![p](https://img.shields.io/badge/Points-70-success) ![c](https://img.shields.io/badge/Crypto-orange)

> What happens if you have a small exponent? There is a twist though, we padded the plaintext so that (M ** e) is just barely larger than N.

We are give `n, c and e` of an RSA problem. . The challenge text says _What happens if you have a small exponent?_ similar to the other MiniRSA challenge, but the message is said to be padded so that _(M ** e) is just barely larger than N_. What does this mean?  
We know that M\*\*e mod N = c, so also M\*\*e = c + x\*N. We need to find that x.

With such big numbers, this equation is like M\*\*e ~= x\*N: so we just need to find the cubic root of x\*N with (in this case) gmpy2: M = iroot(x\*N, 3). We can't know this value a priori but we can bruteforce in with a probably small time, due to the _barely larger_ fact. 

The final script is:
```python
import gmpy2

N = 1615765684321463054078226051959887884233678317734892901740763321135213636796075462401950274602405095138589898087428337758445013281488966866073355710771864671726991918706558071231266976427184673800225254531695928541272546385146495736420261815693810544589811104967829354461491178200126099661909654163542661541699404839644035177445092988952614918424317082380174383819025585076206641993479326576180793544321194357018916215113009742654408597083724508169216182008449693917227497813165444372201517541788989925461711067825681947947471001390843774746442699739386923285801022685451221261010798837646928092277556198145662924691803032880040492762442561497760689933601781401617086600593482127465655390841361154025890679757514060456103104199255917164678161972735858939464790960448345988941481499050248673128656508055285037090026439683847266536283160142071643015434813473463469733112182328678706702116054036618277506997666534567846763938692335069955755244438415377933440029498378955355877502743215305768814857864433151287
e = 3
c = 1220012318588871886132524757898884422174534558055593713309088304910273991073554732659977133980685370899257850121970812405700793710546674062154237544840177616746805668666317481140872605653768484867292138139949076102907399831998827567645230986345455915692863094364797526497302082734955903755050638155202890599808146919581675891411119628108546342758721287307471723093546788074479139848242227243523617899178070097350912870635303707113283010669418774091018728233471491573736725568575532635111164176010070788796616348740261987121152288917179932230769893513971774137615028741237163693178359120276497700812698199245070488892892209716639870702721110338285426338729911942926177029934906215716407021792856449586278849142522957603215285531263079546937443583905937777298337318454706096366106704204777777913076793265584075700215822263709126228246232640662350759018119501368721990988895700497330256765579153834824063344973587990533626156498797388821484630786016515988383280196865544019939739447062641481267899176504155482

for x in range(100000):
    m, found = gmpy2.iroot(x*N + c, e)
    if found:
        print("Found x = {}".format(x))
        print("Flag = {}".format(bytes.fromhex(hex(m)[2:]).decode('ASCII')))
        break
```

Flag: **picoCTF{e_sh0u1d_b3_lArg3r_60ef2420}**

## Dachshund Attacks ![p](https://img.shields.io/badge/Points-80-success) ![c](https://img.shields.io/badge/Crypto-orange)

We have a remote server where we can connect and obtain `e, n and c` of an RSA problem. The challenge text says _What if d is too small?_ (which is oddly ambiguous) and after some googling I found the [Wiener Attack](https://en.wikipedia.org/wiki/Wiener%27s_attack) (more ambiguous), feasible when d is small! If any doubt, this is confirmed from the fact that Dachshund is that little sausage dog, also called wiener dog.  
By searching for a python implementation I found [this one](https://github.com/orisano/owiener) awesome, and I used it to solve the problem.

By setting the given `e` and `n` we can obtain `d` with the attack, and after that we can simply decrypt the given `c`, convert it into hex and then ASCII and get the flag. This is the final script:
```python
import owiener

e = 115672417112927257671680305939934359365770610260861730036576852003995595676738019854156896978452695493499603711084199051703037741612104358554500922255601810699239639276721088454380220351087165317005776882604094492362559466589322345564816722986043365200197328901401825485278698288628276429261242166244230567489
n = 126464990415558983403176864213946695038601049351609225147898757728512524756706217511963198935092618068670554550413258741381432620153181016246126875941976724705392460289282557576686876928892251600322535922349244519540114524945350798877163247781257922671051428624372661514140723871265632532731717598340766266343
c = 111321497464016602005557521031123106684276292631071554434038480623506616443911260308781727450386770672481648306263904680048763443482585922984395943505671937379941613335472362526841433859265067829439266522906203272443815955305450235368266937689107285781709931596212063854029971643694610913742233468948132822071
d = owiener.attack(e, n)

if d is None:
    print("Failed")
else:
    print("Hacked d={}".format(d))

m = pow(c,d,n)

bytes_flag = bytes.fromhex(hex(m)[2:])
flag = bytes_flag.decode("ASCII")

print(flag)
```

Flag: **picoCTF{proving_wiener_6907362}**

## No padding, no problem ![p](https://img.shields.io/badge/Points-90-success) ![c](https://img.shields.io/badge/Crypto-orange)
> Oracles can be your best friend, they will decrypt anything, except the flag's ciphertext. How will you break it? 

If we connect to the server we only get the possibility to submit a ciphertext and get it decrypted, nothing else.  
We have a very important property of RSA, also called the multiplicative property: the multiplication (modulo n) of two ciphertexts is the same as the encryption of the multiplication of the two plaintexts, E(m)\*E(s) mod n = E(m\*s mod n), in fact since E(m)\*E(s) = m^e\*s^e mod n = (m\*s)^e mod n = (m\*s mod n)^e mod n. You can read more [here](http://secgroup.ext.dsi.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html).

We have N, e and ctx_flag, we can exploit the multiplicative property to perform a Chosen Ciphertext Attack on the remote server, choosing ptx2 = 2 and obtaining ctx2 = 2^e mod n; calculate ctx3 = ctx2\*ctx_flag and then submit it to the Oracle getting ptx3. Finally, since ptx3 = ptx2 \* ptx_flag we can get ptx_flag = ptx3 / ptx2

Let's take a look at numbers, from the remote server we get this:
```
n: 80799209814431095790343491259338238651107977352561235864565263656787018421467846733079894989328485497099422410585760003073248073860766557895750352694681971050346253898533173884271409890381084072547226455973760535398079441854389733568634600462617155511458397767430347644255066152450223025245316062323744020151
e: 65537
ciphertext: 40872946028823975975313513670752641684826068380477595686500937086157118355275592497669013278548614810724188401550378935134665758558547491918177306811706097537816022118750118661881706495647706460278367468016154374191035033632334666208160020365739127162462144281924917891906964041444797332706085490053170514935
```

Our calculations are:
```
ctx2 = 2^e mod N = 40935033850459547782904942040359212982473014053363343577187113044679713885186279744481179378912498180180392491144073758870887071124500925648494670883819915615287427404930386571885103041426211042682712925728699844156052023782715880204848567642909212286423862519582644456271219578652991085238899617068058078233

ctx3 = ctx2 * ctx_flag = 30710048674964052826548292045401307845982558650123791385884667431243560854988145736150020129083196263191298375858184314476153189719336525615024282711192479938593621545772507009793907796060288231201251375503929634767178982425215333628709400527885067579789820811531503857728144965096768255334621727074652950165

ptx3 = 580550060391700078946913236734911770139931497702556153513487440893406629034802718534645538074938502890769281669222390720762

ptx_flag = ptx3 / 2 = 290275030195850039473456618367455885069965748851278076756743720446703314517401359267322769037469251445384640834611195360381
```

And if we take the bytes and convert them into ASCII we will obtain the flag, `print(bytes.fromhex(hex(ptx_flag)[2:]))`.

Flag: **picoCTF{m4yb3_Th0se_m3s54g3s_4r3_difurrent_4005534}**

## spelling-quiz ![p](https://img.shields.io/badge/Points-100-success) ![c](https://img.shields.io/badge/Crypto-orange)
> I found the flag, but my brother wrote a program to encrypt all his text files. He has a spelling quiz study guide too, but I don't know if that helps.

I know, this probably is not the cleanest solution, but I would like to share it anyway.

In the .zip file we can see a flag.txt file, so I immediately tried to recognize the algorithm used to encrypt it. Even Cyberchef was not able to get it, so I tried [quipqiup](https://quipqiup.com/) because I was too lazy to do the things myself.  
By inserting our flag and selecting Solve (statistics) we can immediately see a meaningful string (*perhaps_the_dog_jumped_over_was_just_tired*), our flag. I selected statistics because of the keywords **spelling**, making me think about frequency analysis.

It turns out that this is the right path, but notice that I did not even looked at the `encrypt.py` source code or the `study-guide.txt` they provided us. If quipqiup wasn't enough, I could have used the study-guide (a bunch of strings probably encrypted in the same way of the flag) to perform a frequency analysis, and with the results obtain the flag.

Flag: **picoCTF{perhaps_the_dog_jumped_over_was_just_tired}**

## Pixelated ![p](https://img.shields.io/badge/Points-100-success) ![c](https://img.shields.io/badge/Crypto-orange)

This challenge gives us 2 images made by what seem random pixels, suggesting we can extract a flag from them. I immediately thought about performing a bitwise XOR beetween them, but unfortunately this did not work. At this point I was stuck, trying AND and OR operations too without success.  

I then tried to open them on StegSolve, a jar containing a lot of useful steganography tools like in this case the **Image Combiner**: by selecting the ADD operation we get this (I still can't reach the same result with Linux commands):

![image](./pixel.bmp)

So here it is the flag: **picoCTF{2a4d45c7}**

## Play Nice ![p](https://img.shields.io/badge/Points-110-success) ![c](https://img.shields.io/badge/Crypto-orange)
> Not all ancient ciphers were so bad... The flag is not in standard format. nc mercury.picoctf.net 21003 [playfair.py](https://mercury.picoctf.net/static/3329978ea3a249ef44d929b41afc5370/playfair.py)

When connecting we have this, every time:
```
Here is the alphabet: 0uxtb3w4kj26q9m8gioe7nvahplr5dy1fzcs
Here is the encrypted message: xj5c181ropf5xjmyujnv0wlqrjdrbz
What is the plaintext message? 
```

If we take a look at the source code we can see what seems a standard implementation of Playfair, except the fact that the matrix is 6x6 and not the classical 5x5. By just reversing some instructions we can perform the decryption, being alphabet and ciphertext fixed.

```python
#!/usr/bin/python3 -u
import signal

SQUARE_SIZE = 6


def generate_square(alphabet):
	assert len(alphabet) == pow(SQUARE_SIZE, 2)
	matrix = []
	for i, letter in enumerate(alphabet):
		if i % SQUARE_SIZE == 0:
			row = []
		row.append(letter)
		if i % SQUARE_SIZE == (SQUARE_SIZE - 1):
			matrix.append(row)
	return matrix

def get_index(letter, matrix):
	for row in range(SQUARE_SIZE):
		for col in range(SQUARE_SIZE):
			if matrix[row][col] == letter:
				return (row, col)
	print("letter not found in matrix.")
	exit()

def encrypt_pair(pair, matrix):
	p1 = get_index(pair[0], matrix)	# find first letter in the matrix
	p2 = get_index(pair[1], matrix)	# find second letter in the matrix

	# get_index returns the pair (row, col)

	if p1[0] == p2[0]:	# row
		return matrix[p1[0]][(p1[1] + 1)  % SQUARE_SIZE] + matrix[p2[0]][(p2[1] + 1)  % SQUARE_SIZE]
	elif p1[1] == p2[1]:	# col
		return matrix[(p1[0] + 1)  % SQUARE_SIZE][p1[1]] + matrix[(p2[0] + 1)  % SQUARE_SIZE][p2[1]]
	else:
		return matrix[p1[0]][p2[1]] + matrix[p2[0]][p1[1]]

def encrypt_string(s, matrix):
	result = ""
	if len(s) % 2 == 0:
		plain = s
	else:
		plain = s + "0uxtb3w4kj26q9m8gioe7nvahplr5dy1fzcs"[0]	# just append 0 if odd
	for i in range(0, len(plain), 2):
		result += encrypt_pair(plain[i:i + 2], matrix)
	return result

alphabet = open("key").read().rstrip()
m = generate_square(alphabet)	# just create a 6x6 matrix with alphabet letters (we know this)
msg = open("msg").read().rstrip()
enc_msg = encrypt_string(msg, m)
print("Here is the alphabet: {}\nHere is the encrypted message: {}".format(alphabet, enc_msg))
signal.alarm(18)
resp = input("What is the plaintext message? ").rstrip()
if resp and resp == msg:
	print("Congratulations! Here's the flag: {}".format(open("flag").read()))

# https://en.wikipedia.org/wiki/Playfair_cipher
```

Notice that in the code we can also see a comment leading to Playfair cipher on Wikipedia. I then tried to verify if the algorithm was really standard, bruteforcing all the possible decrypted texts, leading to a bunch of strings, among which we can see our previously obtained plaintext value: this was an alternative solution.

```python
SQUARE_SIZE = 6
alphabet = "0uxtb3w4kj26q9m8gioe7nvahplr5dy1fzcs"
enc = "xj5c181ropf5xjmyujnv0wlqrjdrbz"

def generate_square(alphabet):
	assert len(alphabet) == pow(SQUARE_SIZE, 2)
	matrix = []
	for i, letter in enumerate(alphabet):
		if i % SQUARE_SIZE == 0:
			row = []
		row.append(letter)
		if i % SQUARE_SIZE == (SQUARE_SIZE - 1):
			matrix.append(row)
	return matrix


m = generate_square(alphabet)

def get_index(letter, matrix):
	for row in range(SQUARE_SIZE):
		for col in range(SQUARE_SIZE):
			if matrix[row][col] == letter:
				return (row, col)
	print("letter not found in matrix.")
	exit()

def decrypt_pair(pair, matrix):

	p1 = get_index(pair[0], matrix)
	p2 = get_index(pair[1], matrix)

	if p1[0] == p2[0]:	# row
		return matrix[p1[0]][(p1[1] - 1)  % SQUARE_SIZE] + matrix[p2[0]][(p2[1] - 1)  % SQUARE_SIZE]	# invert constants
	elif p1[1] == p2[1]:	# col
		return matrix[(p1[0] - 1)  % SQUARE_SIZE][p1[1]] + matrix[(p2[0] - 1)  % SQUARE_SIZE][p2[1]]	# invert constants
	else:
		return matrix[p1[0]][p2[1]] + matrix[p2[0]][p1[1]]

def decrypt_string(s, matrix):
	result = ""
	for i in range(0, len(s), 2):
		result += decrypt_pair(s[i:i + 2], matrix)
	return result

dec = decrypt_string(enc, m)

print(dec)
```

If we submit this as plaintext we obtain an hex value, and this is the flag because it's not in the usual format: **3f4b60ebf36369258d8638d2038c7ad1**

## Double DES ![p](https://img.shields.io/badge/Points-130-success) ![c](https://img.shields.io/badge/Crypto-orange)

From the source code we can see that it's a quite regular 2DES encryption, despite the fact that the keys are only 6 bytes long instead of the classical 8 bytes. A padding is applied to them and to the plaintext to reach 8 bytes long blocks.

It's well known that **2DES is vulnerable to meet-in-the-middle** attacks. In fact if we look at [Wikipedia](https://en.wikipedia.org/wiki/Meet-in-the-middle_attack) we can see a really handy formula for this challenge.

The fact that the keys are shorter makes the attack even faster. The remote server gives the encrypted flag and let us provide a plaintext to encrypt, giving us the corresponding ciphertext.  
The idea is to get all of this (we can choose the plaintext as we want) and then perform the attack: we will encrypt our plaintext with all the possible keys first, then decrypy the ciphertext with all the possible keys. I saved all the results in a dictionary (`dic`) to get a faster access to the values and have an immediate key-ctx corrispondence.

After that we will compare the results: if there is a match between two of them we will have a candidate key1-key2 couple to use to double decrypt the encrypted flag.

This last step is done by just reversing the given `encrypt_double` function into `decrypt_double` function, while `pad` remains the same.

_Note: normally we would have to test the whole set of candidate keys, while in this challenge we can stop at the first one and get the flag correctly._

This is the script I used (I struggled a lot with payload sending, then I realized it has to be an hex value):
```python
from pwn import *
import itertools
from Crypto.Cipher import DES

menu_end = "Here is the flag:\n"
data_end = "What data would you like to encrypt? "

r = remote("mercury.picoctf.net", 31991)

log.info("Getting encrypted flag...")
r.recvline()
enc_flag = r.recvlineS().strip()
log.success("Encrypted flag = {}".format(enc_flag))

payload = b"ABCDE"
log.info("Sending my custom data ({})...".format(payload))
r.sendlineafter(data_end, enhex(payload))	
enc_payload = r.recvlineS().strip()
log.success("Encrypted payload = {}".format(enc_payload))
enc_payload = bytes.fromhex(enc_payload)

def pad(msg):
    block_len = 8
    over = len(msg) % block_len
    pad = block_len - over
    return (msg + " " * pad).encode()

def double_decrypt(m, key1, key2):
    cipher2 = DES.new(key2, DES.MODE_ECB)
    dec_msg = cipher2.decrypt(m)

    cipher1 = DES.new(key1, DES.MODE_ECB)
    return cipher1.decrypt(dec_msg)

dic = {}

for key1 in map(''.join, itertools.product('0123456789', repeat=6)):
	key1 = pad(key1)
	cipher1 = DES.new(key1, DES.MODE_ECB)
	enc_k1 = cipher1.encrypt(pad(payload.decode()))
	dic[enc_k1] = key1

for key2 in map(''.join, itertools.product('0123456789', repeat=6)):
	key2 = pad(key2)
	cipher2 = DES.new(key2, DES.MODE_ECB)
	dec_k2 = cipher2.decrypt(enc_payload)
	if(dec_k2 in dic):
		key1 = dic[dec_k2]
		log.info("found {} and {} with {}".format(key1,key2,dec_k2))
		log.success(double_decrypt(unhex(enc_flag), key1, key2))
		break
```

Flag (non-standard format): **6d4e063d16d250b953d009e2ef07e241**

## Compress and Attack

We are given a pretty simple source code:
```python
import zlib
from random import randint
import os
from Crypto.Cipher import Salsa20

flag = open("./flag").read()


def compress(text):
    return zlib.compress(bytes(text.encode("utf-8")))

def encrypt(plaintext):
    secret = os.urandom(32)
    cipher = Salsa20.new(key=secret)
    return cipher.nonce + cipher.encrypt(plaintext)

def main():
    while True:
        usr_input = input("Enter your text to be encrypted: ")
        compressed_text = compress(flag + usr_input)
        encrypted = encrypt(compressed_text)
        
        nonce = encrypted[:8]
        encrypted_text =  encrypted[8:]
        print(nonce)
        print(encrypted_text)
        print(len(encrypted_text))

if __name__ == '__main__':
    main() 
```

Salsa20 is used, but unfortunately there are no known vulnerabilities at the moment.

At this point I thought about the fact that maybe there is a reason why they give us the length of the encrypted text: our input is concatenated to the flag and then compressed. Mmmh, let's take a look at how zlib works: reading [this](https://www.euccas.me/zlib/) I focused on this statement, _Codes for more frequently occurring data symbols are shorter than codes for less frequently occurring data symbols._

So probably, knowing that `picoCTF{` is part of the flag for sure, we can exploit this. Let's try to submit that as input and see what happens:

![image](compress.PNG)

In the image above you can see that the two inputs provided, even if of the same size, give us back a really different ciphertext length. Cool, maybe we are on the right path.

I wrote a Python script to see if this really worked, and I initially found `picoCTF{s`. Now I tried to bruteforce all the remaining characters, knowing that the ciphertext lenght must be always 48 and the alphabet is made of letters, underscore and braces (hint).  
I handled the fact that the server will disconnect us after a fixed amount of time by just reconnecting again.

```python
from pwn import *
import string

TARGET_LEN = 48
menu_end = "Enter your text to be encrypted: "
payload = "picoCTF{"
alphabet = string.ascii_letters + "_}"

r = remote("mercury.picoctf.net", 29350)

while(True):
	for char in alphabet:
		try:
			r.sendlineafter(menu_end, payload + char)
			r.recvline() # discard value
			r.recvline() # discard value
			length = int(r.recvlineS().strip()) # get ciphertext length

			if (length == TARGET_LEN):
				payload += char
				log.success(payload)
		except:
			r = remote("mercury.picoctf.net", 29350)
```

Flag: **picoCTF{sheriff_you_solved_the_crime}**