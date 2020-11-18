# m0lecon CTF 2020 Write-ups
Event: **m0lecon CTF 2020, 14-15 October 2020** | [official URL](https://ctf.m0lecon.it/)

Final position: **11th** | [Full Scoreboard here](https://ctf.m0lecon.it/scoreboard)

Our Team: **CangureTheFlat** | [CTFtime page](https://ctftime.org/team/137370)

Formed by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Stefano Armanes](https://github.com/stearm)
* [Stefano Bagarin](https://github.com/stepolimi)
* [Francesco Filippini](https://github.com/filippinifra)

# Write Ups - Categories and Points
## Cryptography

### Babyhash
![c](https://img.shields.io/badge/Cryptography-orange) ![p](https://img.shields.io/badge/Points-114-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_ste-lightgrey)

> Oh no! I've accidentally blacklisted my admin credentials, can you help me to find a way to break in?

We are given a python script with some authentication check with username and password. Let's have a look at a part of the source code:

```python
try:
	print('Username:')
	username = input()
	assert len(username) <= 512
	username = unhexlify(username)
	print('Password:')
	password = input()
	assert len(password) <= 512
	password = unhexlify(password)
except:
	print("Input too long! I can't keep in memory such long data")
	exit()

if username == b'admin' or password == b'password':
	print("Intrusion detected! Admins can login only from inside our LAN!")
	exit()

user_hash = (pow(x, bytes_to_long(username), p) * pow(y, bytes_to_long(password), p)) % p

if user_hash == server_hash:
	print("Glad to see you, admin!\n\n")
	print(flag)
else:
	print("Wrong credentials.")
```

We can see that the flag is printed when user_hash == server_hash. In previous lines we can also see that:
```python
p = 43401284375631863165968499011197727448907264840342630537012422089599453290392542589198227993829403166459913232354777490444915201356560807401141203961578150815557853865678753463969663318864902106651761912058979552119867603661163587639785030788676120329044248495611269533429749805119341551183130515359738240737511058829539566547367223386189286492001611298474857947463007621758421914760578235374029873653721324392107800911728989887542225179963985432894355552676403863014228425990320221892545963512002645771206151750279770286101983884882943294435823971377082846859794746562204984002166172161020302386671098808858635655367
a = bytes_to_long(b'admin')
b = bytes_to_long(b'password')
server_hash = (pow(x, a, p) * pow(y, b, p)) % p
```
But if we try to login with *admin* and *password* (in hexadecimal format) as credentials we get detected and kicked out. 
Then we got the idea: try to add some null bytes before those credentials in order not to trigger the intrusion detection, but at the same time have the same value for *a* and *b* required by the code.

![Alt text](./babyhash.PNG?raw=true "Title")

**ptm{a_b1g_s0phi3_germ41n_pr1m3}**

Note: after the challenge we discovered that our solution was an unintended one but hey, we still got the flag!

### ESCR
![c](https://img.shields.io/badge/Cryptography-orange) ![p](https://img.shields.io/badge/Points-367-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_b4g4-lightgrey)

> Eat, Split, Compress, Repeat.

## Miscellaneous
### Warmup
![c](https://img.shields.io/badge/Miscellaneous-ff69b4) ![p](https://img.shields.io/badge/Points-100-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

> Some of you complained about the "warmup" tag at our m0leCon CTF Teaser. So we made it a challenge.
**ptm{}**

## Reverse Engineering
### The Rickshank Rickdemption
![c](https://img.shields.io/badge/Reverse_Engineering-2c3e50) ![p](https://img.shields.io/badge/Points-179-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_b4g4-lightgrey)

> Welcome to the Rick and Morty universe! The council of Ricks have sent an army of Mortys ready to arrest Rick and cancel the interdimensional cable tv. Defeat them all, reach the last level and try to win. To be fair, you have to have a very high IQ to win.

The game gives the possibility to save the game and load it. By looking at the saved file and the decompiled binary togheter it can be noticed that the file has several fields stored as bytes, and by performing sequential saves of the game we were able to reverse engineer the .sav file and get a knowledge of every field meaning.

The interesting ones are: the level number, the position "x" and "y" of the player in the current level and a checksum made by the hash of the other 3 interesting fields toghether separated by a - character.
With those information, we were able to modify the current level and the checksum accordingly to it. By setting it to 17 (where the last level in the game was 16) and loading the save file, the following screen containing the flag showed up.

![Alt text](./rick_morty_CTF.png?raw=true "Title")

Here is the flag: 

**ptm{_P34ac3_4m0ng_world5_b1c20a1a234a46e26dc7dcbfb69}**
