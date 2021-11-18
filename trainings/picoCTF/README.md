# picoCTF - picoGym
In this section I will store some writeups for the challenges I managed to solve in the picoGym, except the trivial ones.

Authors: 
* [Gregorio Galletti](https://github.com/gregalletti) - _griggoswaggo_ (picoGym Score: **7730**)

# General Skills
### X
![c](https://img.shields.io/badge/General-lightgrey) ![p](https://img.shields.io/badge/Points-350-success)

# Cryptography
### Mind your Ps and Qs
![c](https://img.shields.io/badge/Crypto-orange) ![p](https://img.shields.io/badge/Points-20-success)
> Decrypt my super sick RSA:  
> c: 964354128913912393938480857590969826308054462950561875638492039363373779803642185  
> n: 1584586296183412107468474423529992275940096154074798537916936609523894209759157543  
> e: 65537

We can easily see that, as hinted, the modulus N is too small. In this way we can simply factor it (factordb) and get P and Q.  
Now we can calculate `PHI = (P-1)*(Q-1)` and `D = E^(-1) mod PHI`, to decrypt the given C we just calculate `M = C^D mod N` and convert it into text.

Flag: **picoCTF{sma11_N_n0_g0od_73918962}**


### Easy Peasy
![c](https://img.shields.io/badge/Crypto-orange) ![p](https://img.shields.io/badge/Points-40-success)

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

### Mini RSA
![c](https://img.shields.io/badge/Crypto-orange) ![p](https://img.shields.io/badge/Points-20-success)


# Binary Exploitation
### Stonks
![c](https://img.shields.io/badge/Binary-darkred) ![p](https://img.shields.io/badge/Points-20-success)

We are given a C source file, so let's search for vulnerabilities. There is a clear *format string* vulnerability at line 93, in the `buy_stonks` function:

```c
printf("What is your API token?\n");
scanf("%300s", user_buf);
printf("Buying stonks with token:\n");
printf(user_buf);
```

Now we know we can use this to print what we need from the memory. Let's try locally, using a custom `api` file (the flag one) to easily recognize if we got the content, take a bunch of 'A's to try. If we then submit a sequence of `%x`s as input, we will leak the memory and see a sequence of 41, our flag file.

With no hesitation we can simply connect to the remote program and do the same, leaking at some point (after converting it into ascii) `ocip{FTC0l_I4_t5m_ll0m_y_y3n2fc10a10\xff\xfb\x00}` that is clearly our flag. 

Just reverse it 4 by 4 characters and we obtain the flag: **picoCTF{I_l05t_4ll_my_m0n3y_1cf201a0}**

# Web Exploitation
### X
![c](https://img.shields.io/badge/Web-purple) ![p](https://img.shields.io/badge/Points-350-success)

# Reverse Engineering
### ARMssembly 0
![c](https://img.shields.io/badge/Reverse-lightblue) ![p](https://img.shields.io/badge/Points-40-success)

We have a .S file, so let's open it and start analyzing it, knowing that the arguments are 3854998744 and 915131509.  
Here is the main:
```assembly
main:
	stp	x29, x30, [sp, -48]!
	add	x29, sp, 0
	str	x19, [sp, 16]
	str	w0, [x29, 44]
	str	x1, [x29, 32]
	ldr	x0, [x29, 32]
	add	x0, x0, 8
	ldr	x0, [x0]
	bl	atoi
	mov	w19, w0
	ldr	x0, [x29, 32]
	add	x0, x0, 16
	ldr	x0, [x0]
	bl	atoi
	mov	w1, w0
	mov	w0, w19
	bl	func1
	mov	w1, w0
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	bl	printf
	mov	w0, 0
	ldr	x19, [sp, 16]
	ldp	x29, x30, [sp], 48
	ret
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
	.section	.note.GNU-stack,"",@progbits
```

What the first lines of code seem to do is to read arguments from command line and convert them into integers (notice the double `atoi` link call), and after that we can see `mov    w1, w0` and `mov    w0, w19` leaving the input values in the same order we wrote them: they are then passed to `func1` as parameters with `w0 = 3854998744` and `w1 = 915131509`.  

Here is `func1` and the following functions/labels (`L2`, `L3` and `LC0`): 
```assembly
func1:
	sub	sp, sp, #16
	str	w0, [sp, 12]
	str	w1, [sp, 8]
	ldr	w1, [sp, 12]
	ldr	w0, [sp, 8]
	cmp	w1, w0
	bls	.L2
	ldr	w0, [sp, 12]
	b	.L3
.L2:
	ldr	w0, [sp, 8]
.L3:
	add	sp, sp, 16
	ret
	.size	func1, .-func1
	.section	.rodata
	.align	3
.LC0:
	.string	"Result: %ld\n"
	.text
	.align	2
	.global	main
	.type	main, %function
```

`func1` just loads the two values in reverse order and compares them (now `w0 = 915131509` and `w1 = 3854998744`), if w1 < w0 then jumps to `.L2`: this is not our case. Then the `ldr   w0, [sp, 12]` instruction will load the first value, 3854998744, and jump to `.L3`.

After getting back to the main, this value will be printed. The challenge description says that the flag format is the hex value of what will be printed, so **picoCTF{e5c69cd8}**

### Speeds and feeds
![c](https://img.shields.io/badge/Reverse-lightblue) ![p](https://img.shields.io/badge/Points-50-success)

We connect to a remote server and we get as result a veeeery long output, let's write it on a file and take a look. We can immediately see every lines starts with G, and then X/Y/Z and some numerical values: this is G-Code, used by 3D printers (luckily enough I already solved a G-Code challenge).

We can then paste the code on [this](https://ncviewer.com/) Simulator and view the result: 
![image](./speeds.PNG)

Flag: **picoCTF{num3r1cal_c0ntr0l_68a8fe29}**

### ARMssembly 1
![c](https://img.shields.io/badge/Reverse-lightblue) ![p](https://img.shields.io/badge/Points-70-success)

This challenge is very similar to ARMssembly 0, so we can use the same approach.  
Here is the main:
```assembly
main:
	stp	x29, x30, [sp, -48]!
	add	x29, sp, 0
	str	w0, [x29, 28]
	str	x1, [x29, 16]
	ldr	x0, [x29, 16]
	add	x0, x0, 8
	ldr	x0, [x0]
	bl	atoi
	str	w0, [x29, 44]
	ldr	w0, [x29, 44]
	bl	func
	cmp	w0, 0
	bne	.L4
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	bl	puts
	b	.L6
```

The `bne    .L4` is what we want to avoid, because it will lead to `.LC1` printing "You Lose :(". We want instead not to take that branch and jump to `.LC0` printing "You Win!": we need w0 = 0 (the result of `func`).
```assembly
func:
	sub	sp, sp, #32
	str	w0, [sp, 12]	; this is the needed argument, call it x
	mov	w0, 58
	str	w0, [sp, 16]	; store 58 
	mov	w0, 2
	str	w0, [sp, 20]	; store 2
	mov	w0, 3
	str	w0, [sp, 24]	; store 3
	ldr	w0, [sp, 20]	; w0 = 2
	ldr	w1, [sp, 16]	; w1 = 58
	lsl	w0, w1, w0	; w0 = 58 << 2 = 58 * 4 = 232
	str	w0, [sp, 28]	; store 232
	ldr	w1, [sp, 28]	; w1 = 232
	ldr	w0, [sp, 24]	; w0 = 3
	sdiv	w0, w1, w0	; w0 = 232 / 3
	str	w0, [sp, 28]	; store 77
	ldr	w1, [sp, 28]	; w1 = 77
	ldr	w0, [sp, 12]	; w0 = x
	sub	w0, w1, w0	; w0 = 77 - x
	str	w0, [sp, 28]	; store (77 - x)
	ldr	w0, [sp, 28]	; w0 = (77 - x)
	add	sp, sp, 32
	ret
	.size	func, .-func
	.section	.rodata
	.align	3
```

The comments I added to the assembly code are self-explanatory, in this case we have that (77 - x) must be equal to 0, leading to `x = 77`. 77 in hex is 4d, thus the flag (lowercase and 8 bit) will be **picoCTF{0000004d}**

# Forensics
### tunn3l v1s10n
![c](https://img.shields.io/badge/Forensics-blue) ![p](https://img.shields.io/badge/Points-40-success)

The given file has no extension and strings or other commands seems not to lead to something useful, so let's try to find a suitable file format through `exiftool`. The result suggest this is a BMP file, and we are quite sure about it by opening it with an hex editor: the magic bytes are correct (42 4d, 'BM') so we will probably need to "fix" this file to obtain the flag.

Let's start to analyze it, and we can soon see two bad00000 patterns, indicating that these are the bytes we need to fix: 

`00000000  42 4d 8e 26 2c 00 00 00  00 00 ba d0 00 00 ba d0  |BM.&,...........|`, so according to BMP files structure we have: 
- 42 4d = _Signature_
- 8e 26 2c 00 = _File size_
- 00 00 = _Reserved 1_
- 00 00 = _Reserved 2_
- ba d0 00 00 = _File Offset to pixel array_
- ba d0 00 00 = _DIB Header Size_

I have no idea of what this means, so let's try to google it and get a better undestanding: from [here](http://www.ece.ualberta.ca/~elliott/ee552/studentAppNotes/2003_w/misc/bmp_file_format/bmp_file_format.htm) we get to know that _DIB Header Size_ turns out to be a constant equal to 40 (0x28), and _File Offset_ the distance from the beginning of the file to the actual image data, so 14 (Header size) + 40 (InfoHeader size) = 54 (0x36), both of them composed of 4 bytes so we need to apply some padding with 00 bytes.

Unfortunately at this point the image is displayed correctly but we are getting trolled, let's keep digging (we know we are on the right way).

![image](./tunnel1.bmp)

After trying some steganography tools on that, by checking again `exiftool` tells us that the image is 1134 x 306 with a size of 2893400. This is pretty suspicious, indicating that maybe this is not the real resolution: we can easily see that by incrementing the height we can see a meaningful higher image and by setting this value as 42 03 we can see the flag.

![image](./tunnel2.bmp)

Flag: **picoCTF{qu1t3_a_v13w_2020}**

### MacroHard WeakEdge
![c](https://img.shields.io/badge/Forensics-blue) ![p](https://img.shields.io/badge/Points-60-success)

We are given a Powerpoint file with macros (.pptm), this seems like a "classic" MS Office malware challenge. By opening the file with Powerpoint on Windows I could not see all macros, only a `not_flag() one`, clearly not the flag.

PPTM files use ZIP and XML to compress and organize the data into a single file, so I decided to analyze the file with `binwalk`: after loads of zip archives representing the various slides and their content, two interesting ones are displayed: `ppt/vbaProject.bin` and `ppt/slideMasters/hidden`.

The first one should contain macros, but given that somehow they are hidden I decided to first check the second one. This turns out right, because looking at the `hidden` file we can see `Z m x h Z z o g c G l j b 0 N U R n t E M W R f d V 9 r b j B 3 X 3 B w d H N f c l 9 6 M X A 1 f Q` as result.  
This looks like base64, so removing spaces and decoding it will lead to the flag: 
```bash
cat ppt/slideMasters/hidden | tr -d ' ' | base64 -d
```
Flag: **picoCTF{D1d_u_kn0w_ppts_r_z1p5}**

### Trivial Flag Transfer Protocol
![c](https://img.shields.io/badge/Forensics-blue) ![p](https://img.shields.io/badge/Points-90-success)

We are given a .pcap file, by opening it on Wireshark I immediately saw the TFTP protocol, and following the various treams it seems to exchange some files. Remember that ith TFTP we can not encrypt in any way, so we can easily access those files with `File > Export Objects > TFTP`, getting some interesting ones.

The first one is `instructions.txt`, saying: `GSGCQBRFAGRAPELCGBHEGENSSVPFBJRZHFGQVFTHVFRBHESYNTGENAFSRE.SVTHERBHGNJNLGBUVQRGURSYNTNAQVJVYYPURPXONPXSBEGURCYNA`. This seems a rotation cipher (yes, ROT13) actually saying: `TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN`. Plan, huh?

This gets my attention because we have another file `plan`, and by opening it we get `VHFRQGURCEBTENZNAQUVQVGJVGU-QHRQVYVTRAPR.PURPXBHGGURCUBGBF`, again with ROT13 we get `IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS`. 

We still have one `program.deb` and 3 photos, all seems so be right.

At the time of the challenge I had no access to my Linux VM, so I just tried to "decode" the images to see if they contained some sort of steganography. It turns out that the `picture3.bmp` hides the flag, so probably the `program.deb` is a debian package of steghide. 

Using [this](https://futureboy.us/stegano/decinput.html) online tool and the password DUEDILIGENCE i managed to extract the flag: **picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}**

