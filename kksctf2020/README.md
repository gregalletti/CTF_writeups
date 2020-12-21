# \# kksctf open 2020 Write-ups
Event: **kksctf open 2020, 12-13 December 2020** | [official URL](https://open.kksctf.ru/tasks)

Final position: **26th** | [Full Scoreboard here](https://ctftime.org/event/1112)

Our Team: **CangureTheFlat** | [CTFtime page](https://ctftime.org/team/137370)

Formed by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Marco Gasperini](https://github.com/marcuz1996)
* [Stefano Bagarin](https://github.com/stepolimi)
* [Cristian Spagnuolo](https://github.com/cris96spa)

# Write Ups - Categories and Points
## Web

### Lynx
![c](https://img.shields.io/badge/Web-green) ![p](https://img.shields.io/badge/Points-204-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Hello! We're BluePeace organisation, and we introduce the new project - Lynx Forum!
>
> http://tasks.kksctf.ru:30070/

We access the page, and it says we are not Lynx. 

We know that Lynx is a web browser (rapidly googling confirms it) and so we immediately think about changing the user agent. In fact, by putting ```Lynx/2.8.7rel.1 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/1.0.2a``` and refreshing the page we have something new, telling us something about robots. 

Nice, let's go to the ```robots.txt``` page and see what we get: ```Disallow /a4d81e99fda29123aee9d4bb.```

By just accessing this path we obtain the flag: **kks{s0m3_CLI_br0ws3rs_4r3_us3ful}**

### Cypherpunk2077
![c](https://img.shields.io/badge/Web-green) ![p](https://img.shields.io/badge/Points-392-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> If you have found any bugs in latest AAA projects, please report them using this pretty good service.
>
> http://tasks.kksctf.ru:30030/

Let's first get a general idea of this website. It seems to have just two sections: Report and Keys. 

By just inspecting the code we can see that a line of code is commented, and if we access it we can retreive the Private key of the server. Then we have the Public key, and the possibility to send a report to the server. 

That's all we need, because no direct attacks (like XSS,...) seem to work here, we will try to get some reports (by just changing the URL with a different id) and get a better idea of the content. By doing that manually for the first 10 reports we see that the author name is pretty strange to be written by some other team member, and by decrypting the report content we can notice that a lot of words are repeated. 

The solution here was pretty simple: we made a ```Python``` script to extract all the reports from the server, decrypt and print them with name and content. 

Here is the script:
```python
import requests
import json
import pgpy

f = open("./output.txt", "w")
	
for i in range(1, 1900):
	r = requests.get("http://tasks.kksctf.ru:30030/reports/{0}".format(i))
	
	author = r.text.split("Name: ")[1].split(" <br>")[0]

	f1 = open("./demofile2.gpg", "w")
	f1.write(r.text.split("<pre> ")[1].split(" </pre>")[0])
	f1.close()

	encrypted_txt_msg = pgpy.PGPMessage.from_file("./demofile2.gpg")

	prv_key, _ = pgpy.PGPKey.from_file("./privkey.gpg")

	decrypted_txt_msg = prv_key.decrypt(encrypted_txt_msg)
	
	f.write(author + " : " + decrypted_txt_msg.message.decode("utf-8") + '\n')
  
f.close()
```
And here is the flag: **kks{in_2077_what_makes_someon3_a_ctf_player7_getting_flag}**

## Other
### Motor Sounds
![c](https://img.shields.io/badge/Other-blue) ![p](https://img.shields.io/badge/Points-268-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Zhzhzhzhzhzhzhzhzhzh, viiiiv, viiiiv, zzhzhzhzhzhzhzh ...

### Blind Shell
![c](https://img.shields.io/badge/Other-blue) ![p](https://img.shields.io/badge/Points-345-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0,_cri-lightgrey)

> It's simple enough, either you've succeeded or you've failed.
>
> Connect here: nc tasks.kksctf.ru 30010

### Encrypted Storage 1
![c](https://img.shields.io/badge/Other-blue) ![p](https://img.shields.io/badge/Points-359-success) ![a](https://img.shields.io/badge/author-marcuz-lightgrey)

> Our client was attacked by some ransomware. Maybe it was separatist dwarves?
>
> He send us encrypted filesystem. Decrypt it, he need some data from secure storage.

### Encrypted Storage 2
![c](https://img.shields.io/badge/Other-blue) ![p](https://img.shields.io/badge/Points-367-success) ![a](https://img.shields.io/badge/author-marcuz-lightgrey)

> Sometimes stupid hackers leave behind signatures that can be used to find them - the one that wrote ransomware is no exception.

Flag: **kks{1_w4s_h3r3!}**


### Red Green Blue Cadets
![c](https://img.shields.io/badge/Other-blue) ![p](https://img.shields.io/badge/Points-411-success) ![a](https://img.shields.io/badge/author-b4g4,_grigg0swagg0-lightgrey)

> Our spy take this picture from KGB special school. They have strange uniform, doesn't it?

Flag: **kks{s4lut3_t0_c4d3ts!}**


## Unsolved Challenges
Unfortunately, we did not manage to solve some challenges that were pretty feasible for us. Here I will put the writeups anyway because they may be helpful sooner or later.

### Bson
**Reason of failure**: 

### not_a_terminator
**Reason of failure**: no one in the team has ever watched Alien vs Predator movie. Pretty sad..



