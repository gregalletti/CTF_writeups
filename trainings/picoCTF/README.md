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

