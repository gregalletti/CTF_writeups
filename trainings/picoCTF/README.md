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
> sdsd

We can easily see that, as hinted, the modulus N is too small. In this way we can simply factor it (factordb) and get P and Q. 

Now we can calculate PHI = (P-1)\*(Q-1) and D = E^(-1) mod PHI, to decrypt the given C we just calculate M = C^D mod N.

Flag: **picoCTF{sma11_N_n0_g0od_73918962}**


# Binary Exploitation
### Stonks
![c](https://img.shields.io/badge/Binary-red) ![p](https://img.shields.io/badge/Points-20-success)

# Web Exploitation
### X
![c](https://img.shields.io/badge/Web-purple) ![p](https://img.shields.io/badge/Points-350-success)

# Reverse Engineering
### X
![c](https://img.shields.io/badge/Reverse-blue) ![p](https://img.shields.io/badge/Points-350-success)

