# CTF InterIUT 2020 Write-ups
Event: **CTF InterIUT 2020, 27-29 November 2020** | [official URL](https://metactf.com/cybergames)

Final position: **** | [Full Scoreboard here](https://ctftime.org/event/1176)

Our Team: **CangureTheFlat** | [CTFtime page](https://ctftime.org/team/137370)

Formed by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Marco Gasperini](https://github.com/marcuz1996)
* [Stefano Bagarin](https://github.com/stepolimi)
* [Cristian Spagnuolo](https://github.com/filippinifra)

## Introduction Challenge
> At the moment of the team registration, we were given an introductive challenge that you can find here: https://pastebin.com/raw/1BZZyE8K

> Of course this was not part of the CTF itself, but we solved it anyway.

I immediately tried to save the string and open it, resulting in an ELF file. Ok, so now we can try to debug it and to disassemble it.

I used Ghidra to disassemble the code and try to understand it, and gdb with pwntools to play a bit with the execution. So that was a classic input problem, where we have to send a specific input to the program in order to get the "You Won" output, and our input would be the flag.

Knowing that I tried to get a basic knowledge of the code: input required length and other contraints..

# Write Ups - Categories and Points
## Forensics

### Exfiltration 1
![c](https://img.shields.io/badge/Forensics-green) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Description

For this challenge, we had do download a torrent containing a WireShark capture file. By going thorught the downloaded files in the packets exchange in WireShark, we found a python script called the_game.py downloaded by monkey.bzh:8080. We downloaded the file ourselves and, with a fast look at it, it became clear that it was the malware.

![Alt text](./exfiltration1.PNG?raw=true "Title")

The flag was simply the name of the malware between "H2G2{}", so it was: 

**H2G2{the_game.py}**

### Exfiltration 2
![c](https://img.shields.io/badge/Forensics-green) ![p](https://img.shields.io/badge/Points-100-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Description

This is the second of the three Exfiltration challenges.
For this part, our goal was to find the name of the files exfiltrated by the malware. As first thing, we looked at the malicious script and we found out that that script first sends a string containing the name of the file, then the encrypted bytes of the file one at a time, and last a string to terminate it throught the DNS protocol.
As next step we retrieved the ip address of monkey.bhz and added the filter "ip.dst == 172.25.0.2 and !icmp and !tcp" in the packet capture of Wire Shark to see only the packets sent to the ip address of our interest with the UDP protocol.
Giving to the diltered packets a closer look, we recognized that all of them had the same name format, so by ordering them by name, we identified 6 packets that was different named: those had to be the packets of start and end of 3 file transmissions.

![Alt text](./exfiltration2.PNG?raw=true "Title")

The names of the starting packets are:

U3RhcnRpbmcgZXhmaWx0cmF0aW9uIG9m.IHRoZSBmaWxlIC9ob21lL0JyaWFuLy5z.ZWNyZXQvQ29uZmlkZW50aWFsLnBkZg==.monkey.bzh
U3RhcnRpbmcgZXhmaWx0cmF0aW9uIG9m.IHRoZSBmaWxlIC9ob21lL0JyaWFuLy5z.ZWNyZXQvQ29uZmlkZW50aWFsLmpwZw==.monkey.bzh
U3RhcnRpbmcgZXhmaWx0cmF0aW9uIG9m.IHRoZSBmaWxlIC9ob21lL0JyaWFuLy5z.ZWNyZXQvZmxhZy50eHQ=

By taking off ".monkey.bzh" and decoding them from base64 with a simple online tool, we found:

Starting exfiltration of the file /home/Brian/.secret/Confidential.pdf
Starting exfiltration of the file /home/Brian/.secret/Confidential.jpg
Starting exfiltration of the file /home/Brian/.secret/flag.txt

All we had to do now was extracting the file names from the string and put them into our flag format obtaining:

**H2G2{Confidential.pdf,Confidential.jpg,flag.txt}**
