# picoCTF - picoGym
In this section I will store some writeups for the challenges I managed to solve in the picoGym, except the trivial ones.

Authors: 
* [Gregorio Galletti](https://github.com/gregalletti)


# General Skills
### X
![c](https://img.shields.io/badge/General-grey) ![p](https://img.shields.io/badge/Points-350-success)

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
![c](https://img.shields.io/badge/Binary-red) ![p](https://img.shields.io/badge/Points-20-success)

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
### X
![c](https://img.shields.io/badge/Reverse-blue) ![p](https://img.shields.io/badge/Points-350-success)

