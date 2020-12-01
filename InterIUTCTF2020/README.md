# CTF InterIUT 2020 Write-ups
Event: **CTF InterIUT 2020, 27-29 November 2020** | [official URL](https://metactf.com/cybergames)

Final position: **26th** | [Full Scoreboard here](https://ctftime.org/event/1176)

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

This is the first of the three Exfiltration challenges.
For this challenge, we had do download a torrent containing a WireShark capture file. By going thorugh the downloaded files in the packets exchange in WireShark, we found a python script called the_game.py downloaded by monkey.bzh:8080. We downloaded the file ourselves and, with a fast look at it, it became clear that it was the malware.

![Alt text](./exfiltration1.PNG?raw=true "Exfiltration1")

The flag was simply the name of the malware between "H2G2{}", so it was: 

**H2G2{the_game.py}**

### Exfiltration 2
![c](https://img.shields.io/badge/Forensics-green) ![p](https://img.shields.io/badge/Points-100-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Description

This is the second of the three Exfiltration challenges.
For this part, our goal was to find the name of the files exfiltrated by the malware. As first thing, we looked at the malicious script and we found out that that script first sends a string containing the name of the file, then the encrypted bytes of the file one at a time, and last a string to terminate it throught the DNS protocol.
As next step we retrieved the ip address of monkey.bhz and added the filter "ip.dst == 172.25.0.2 and !icmp and !tcp" in the packet capture of Wire Shark to see only the packets sent to the ip address of our interest with the UDP protocol.
Giving to the filtered packets a closer look, we recognized that all of them had the same content format, so by ordering them by info, we identified 6 packets that had different named: those had to be the packets of start and end of 3 file transmissions.

![Alt text](./exfiltration2.PNG?raw=true "Exfiltration2")

The names of the starting packets are:

U3RhcnRpbmcgZXhmaWx0cmF0aW9uIG9m.IHRoZSBmaWxlIC9ob21lL0JyaWFuLy5z.ZWNyZXQvQ29uZmlkZW50aWFsLnBkZg==.monkey.bzh  
U3RhcnRpbmcgZXhmaWx0cmF0aW9uIG9m.IHRoZSBmaWxlIC9ob21lL0JyaWFuLy5z.ZWNyZXQvQ29uZmlkZW50aWFsLmpwZw==.monkey.bzh  
U3RhcnRpbmcgZXhmaWx0cmF0aW9uIG9m.IHRoZSBmaWxlIC9ob21lL0JyaWFuLy5z.ZWNyZXQvZmxhZy50eHQ=.monkey.bzh  

By taking off ".monkey.bzh" and decoding them from base64 with a simple online tool, we found:

Starting exfiltration of the file /home/Brian/.secret/Confidential.pdf  
Starting exfiltration of the file /home/Brian/.secret/Confidential.jpg  
Starting exfiltration of the file /home/Brian/.secret/flag.txt  

All we had to do now was extracting the file names from the string and put them into our flag format and we obtained:

**H2G2{Confidential.pdf,Confidential.jpg,flag.txt}**

### Exfiltration 3
![c](https://img.shields.io/badge/Forensics-green) ![p](https://img.shields.io/badge/Points-100-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Description

This is the third of the three Exfiltration challenges.
The goal of this last part was to retrieve the exfiltrated files and find a flag in those documents. We saw immediatelly that one of the stolen files was called flag.txt and it consisted in only 40 transmitted packets, so we went ahead, wrote a simple python script to revert the encodind made by the malware to each byte of the file before sending it and launched it on the flag packets.  
With our surprise, we received this as output:  

*flag.txt*  

> H2G2{This_is_not_the_flag_¯\_(ツ)_/¯}

Sadly it was just a bait.  

At this point we decided to export from WireShark all the packets of the three files in a json format (which can be found in the maliciousPackets.rar archieve) and to modify our script to take the content of each packet from it to ultimately reconstruct the documents.  
The final script is:  

```python
#!/usr/bin/env python3

from binascii import *
import base64
import json

count = 0
f1 = open("Confidential.pdf","wb")
f2 = open("Confidential.jpg","wb")
f3 = open("flag.txt","wb")

with open('./allPackets.json') as json_file:
  data = json.load(json_file)
  for p in data:
    bigNum = ""  
    prevMonkey = "🙈"
    prev = False
    num = 0

    keys = list(p['_source']['layers']['dns']['Queries'].keys())[0]
    index = str(p['_source']['layers']['dns']['Queries'][keys]['dns.qry.name']).find(".monkey")
    message = str(p['_source']['layers']['dns']['Queries'][keys]['dns.qry.name'])[0:index]

    if(not message[0] == '8' ):
        count +=1
        continue

    monkeyList = base64.b64decode(message.encode("utf-8")).decode()

    for monkey in monkeyList:
      if monkey == "🙊":
        if prevMonkey == "🙊":
             prev = True
             bigNum += str(num)
             num = 0
      if monkey == "🙈":
        num += 5
      if monkey == "🙉":
        num +=1
      if not prev :
         prevMonkey = monkey
      else:
         prevMonkey = "🙈"
         prev = False

    decAscii = int(round(pow(int(bigNum), 1/3),1))
    hexa = str(hex(decAscii)[2:])
    if(len(hexa) != 2):
        hexa = "0" + hexa
    
    char = unhexlify(hexa)
    if(count == 1):
    	f1.write(char)
    if(count == 3):
        f2.write(char)
    if (count == 5):
        f3.write(char)
 
f1.close()
f2.close()
f3.close()
```

Onece launched, after a minute it gave us the following outputs:


*Confidenial.jpg*  

![Alt text](./Confidential.jpg?raw=true "Confidential")


*Content of flag.txt*  

> H2G2{This_is_not_the_flag_¯\_(ツ)_/¯}


*Content of Confidential.pdf*  

> This Flag is confidential : H2G2{DN5_3xf1l7r4710n_15_funny!!!}  


So the flag was contained in the .pdf and it was: 

**H2G2{DN5_3xf1l7r4710n_15_funny!!!}**

## Cryptography

### SAGE 1
![c](https://img.shields.io/badge/Cryptography-orange) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)
> Description
https://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/public_key/blum_goldwasser.html

small N => te lo pigli nel culo

Flag: H2G2{0k_B0om3R}

### SAGE 2
![c](https://img.shields.io/badge/Cryptography-orange) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)
> Description
https://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/classical.html

Flag: 

### Homo
![c](https://img.shields.io/badge/Cryptography-orange) ![p](https://img.shields.io/badge/Points-50-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)
> Description

3638-4738-6454

POST /transactions/make HTTP/1.1
Host: homo-accerus.interiut.ctf
User-Agent: Bank/5.0 (x64; rv:85.0) Masterfox/83.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 687
Content-Type: application/x-www-form-urlencoded

sender=2021-6329-0004&receiver=3638-4738-6454&rsa-encrypted-amount=62508003691955481690418901955121795568007256515741783155795444245740636426057547904329949383645124412455925887910924422648916791078340467132412323560710978587121861334956401507516587624120449879418813403070550485792604237611403907218111719508751300849137282838643224414695053627144165528294962256617439047092392029968770700080403581271667805269164654784974860506346245830305667955665133964758035692743329015828920734126548722790007590931405240654421621913828190132402835380728007018161783200211722413959807646492280466745701690396058608241960771610594344496541655043663887677078699101112740215664968380850617448985390600

Flag: H2G2{HOMO_BRO_<3}
