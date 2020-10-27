# MetaCTF CyberGames 2020 Write-ups
Event: **MetaCTF CyberGames 2020, 24-25 October 2020** | [official URL](https://metactf.com/cybergames)

Final position: **32th in Students-only Scoreboard, 49th in Global Scoreboard** | [Full Scoreboard here](https://ctftime.org/event/1106)

Our Team: **CangureTheFlat** | [CTFtime page](https://ctftime.org/team/137370)

Formed by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Marco Gasperini](https://github.com/marcuz1996)
* [Stefano Bagarin](https://github.com/stepolimi)
* [Francesco Filippini](https://github.com/filippinifra)

# Write Ups - Categories and Points
## Cryptography

### Blake's secret message
![c](https://img.shields.io/badge/Cryptography-orange) ![p](https://img.shields.io/badge/Points-350-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)
The challenge started with a file containing bunch of alphanumerical strings, and 4 strings that were the first 4 strings in the file; the challenge name also states "Blake" which could refer to an hashing algorithm, interesting.

After a quick analysis I noticed that their length was repeated in a cyclic way, so maybe this was a clue: I calculated their length, and the result was:
* 1st string: 128 chars
* 2nd string: 40 chars
* 3rd string: 64 chars
* 4th string: 64 chars
* and then repeated  

Given the nature of the strings and their length, the supposition that they were hashes of some well-known algorithm was stronger, and in particular I was pretty sure that the 2nd one was SHA1.

The challenge said *"You'll need to iteratively break each hash from here, but once you break the one hash, you can break the next one just by adding one more character."*, so I thought that by recognizing this string I would have been able to recognize also the other 3 given.

I then tried to bruteforce it (*da39a3ee5e6b4b0d3255bfef95601890afd80709*), resulting in an empty string hashed with SHA1. Ok so maybe also the other 3 correspond to an empty string? 
The answer was yes, and by simply trying I was able to pull out also the other used algorithms, reaching this situation:
* 1st string: Blake 2b Hash
* 2nd string: SHA1
* 3rd string: SHA256
* 4th string: SHA3-256

From now on it was pretty easy: we knew the algorithms and that we had to always add only a new character.
We submitted this as the last flag, and to be honest we were so tired that we didn't even feel like to write a python script to do that. We bruteforced all the following characters until we blocked for some reason, and the admins told us to submit the flag anyway. 

Partial (or maybe final) flag: 

**MetaCTF{it333r@@@tive_ha$$hing_wor-ks_w0nders_78h2brfdjaq_!**

## Forensics
### Open Thermal Exhaust Port
![c](https://img.shields.io/badge/Forensics-ff69b4) ![p](https://img.shields.io/badge/Points-275-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)
We were given a pcap file with loads of packets involved. I opened the file with Wireshark and instantly filtered on TCP packets only. 
Firstly I tried to analyze the traffic manually, but I soon realized that this was unfeasible (yes it took me a while to realize, but It was 4 am for me come on).

Then I tried to use the filter option to get only the open ports but I had no idea on how to use it, so I had to get them in another way. I remembered that, when a port on a server is open, the number of packets in a single communication will be at least 3: SYN, SYN-ACK, ACK.
I then displayed all the conversations, selected TCP, and ignored all of them with packet number less than 3. For the remaining ports (80, 443, 23, 21, 53, 22, 3128) I checked if the number of packets actually represented the fact that the port was open, in order to avoid possible packet retransmissions.

All of them were good so the solution is simply the sum: 

**MetaCTF{3770}**

## Reconnaissance
### Finding Mr. Casyn
![c](https://img.shields.io/badge/Reconnaissance-blue) ![p](https://img.shields.io/badge/Points-275-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

### Ring Ring
![c](https://img.shields.io/badge/Reconnaissance-blue) ![p](https://img.shields.io/badge/Points-325-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

### Complete Transparency
![c](https://img.shields.io/badge/Reconnaissance-blue) ![p](https://img.shields.io/badge/Points-325-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

### Hangout Spots
![c](https://img.shields.io/badge/Reconnaissance-blue) ![p](https://img.shields.io/badge/Points-525-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

## Other
### Watermarked
![c](https://img.shields.io/badge/Other-18bc9c) ![p](https://img.shields.io/badge/Points-250-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

### Checkmate in 1
![c](https://img.shields.io/badge/Other-18bc9c) ![p](https://img.shields.io/badge/Points-350-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)
I started by counting the length of the given string (27) trying to see of It was somehow a well known length, but no. After downloading the pictures given in the challenge, I saw that they were chess games situations. Despite I did not actually read the name of the challenge, I figured out that they were a sort of chess quiz with White winning in one move.
There were 9 pictures, so finding a way to extract 3 characters from every pic would have been a good start.
Then I proceeded by easily solving them (I often play chess and solve this type of quiz), writing down every winning move in the standard chess notation like Qh7 = Queen moves in h7.

In the meanwhile one of my teammates randomly tried to decrypt the given string with a ROT decryption, discovering some interesting characters like { and }. Looks like a flag :smirk:

Knowing that, we guessed a possible shift correlation between the original string and the chess-obtained string, and observing the outcome of some experiments it turned out that only the numerical characters of the second one were relevant.
So: we grouped both strings in 9 groups of 3 chars, took every group of the first string and shifted by the last char of the corresponding group of the second string.

An easy calculation and the flag is here: 

**MetaCTF{99_p3rc3nt_t4ct1cs}**

## Reverse Engineering
### [REDACTED]
![c](https://img.shields.io/badge/Reverse_Engineering-2c3e50) ![p](https://img.shields.io/badge/Points-225-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

### Password Here Please
![c](https://img.shields.io/badge/Reverse_Engineering-2c3e50) ![p](https://img.shields.io/badge/Points-325-success) ![a](https://img.shields.io/badge/author-b4g4-lightgrey)
The challenge consinsted in reverse engineering a python code to find the string that gets throught each check. The first step was just understanding that the problem could be divided in 4 parts.

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

