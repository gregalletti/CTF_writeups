# MetaCTF CyberGames 2020 Write-ups
Event: **MetaCTF CyberGames 2020, 24-25 October 2020**

Final position: **32th in Students-only Scoreboard, 49th in Global Scoreboard**

Our Team: **CangureTheFlat**

Formed by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Marco Gasperini](https://github.com/marcuz1996)
* [Stefano Bagarin](https://github.com/stepolimi)
* [Francesco Filippini](https://github.com/filippinifra)

# Write Ups - Categories and Points
## Cryptography

### Blake's secret message - 350 pts 
#### author: grigg0swagg0
The challenge started with a file containing bunch of alphanumerical strings, and 4 strings that were the first 4 strings in the file; the challenge name also states "Blake" which could refer to an hashing algorithm, interesting.

After a quick analysis I noticed that their lenght was repeated in a cyclic way, so maybe this was a clue: I calculated their lenght, and the result was:
* 1st string: 128 chars
* 2nd string: 40 chars
* 3rd string: 64 chars
* 4th string: 64 chars
* and then repeated  

Given the nature of the strings and their lenght, the supposition that they were hashes of some well-known algorithm was stronger, and in particular I was pretty sure that the 2nd one was SHA1.

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
### Open Thermal Exhaust Port - 275 pts
#### author: grigg0swagg0
We were given a pcap file with loads of packets involved. I opened the file with Wireshark and instantly filtered on TCP packets only. 
Firstly I tried to analyze the traffic manually, but I soon realized that this was unfeasible (yes it took me a while to realize, but It was 4 am for me come on).

Then I tried to use the filter option to get only the open ports but I had no idea on how to use it, so I had to get them in another way. I remembered that, when a port on a server is open, the number of packets in a single communication will be at least 3: SYN, SYN-ACK, ACK.
I then displayed all the conversations, selected TCP, and ignored all of them with packer number less than 3. For the remaining ports (80, 443, 23, 21, 53, 22, 3128) I checked if the number of packets actually represented the fact that the port was open, in order to avoid possible packet retransmissions.

All of them were good so the solution is simply the sum: 
**MetaCTF{3770}**

## Reconnaissance
### Complete Transparency - 325 pts
#### author: grigg0swagg0

### Finding Mr. Casyn - 275 pts
#### author: grigg0swagg0

### Ring Ring - 325 pts
#### author: grigg0swagg0

### Hangout Spots - 525 pts
#### author: grigg0swagg0

## Other
### Watermarked - 250 pts
#### author: grigg0swagg0

### Checkmate in 1 - 350 pts
#### author: grigg0swagg0
I started by counting the length of the given string (27) trying to see of It was somehow a well known length, but no. After downloading the pictures given in the challenge, I saw that they were chess games situations. Despite I did not actually read the name of the challenge, I figured out that they were a sort of chess quiz with White winning in one move.
There were 9 pictures, so finding a way to extract 3 characters from every pic would have been a good start.
Then I proceeded by easily solving them (I often play chess and solve this type of quiz), writing down every winning move in the standard chess notation like Qh7 = Queen moves in h7.

In the meanwhile one of my teammates randomly tried to decrypt the given string with a ROT decryption, discovering some interesting characters like { and }. Looks like a flag ;)

Knowing that, we guessed a possible shift correlation between the original string and the chess-obtained string, and observing the outcome of some experiments it turned out that only the numerical characters of the second one were relevant.
So: we grouped both strings in 9 groups of 3 chars, took every group of the first string and shifted by the last char of the corresponding group of the second string.

An easy calculation and the flag is here: 
**MetaCTF{}**

## Reverse Engineering
### [REDACTED] - 225 pts
#### author: grigg0swagg0

### [Password Here Please] - 325 pts
#### author: baga
