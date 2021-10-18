# Reply Cybersecurity challenge 2021 Write-ups
Event: **Reply Cybersecurity Challenge, 15-16 October 2021** | [official URL](https://challenges.reply.com/tamtamy/challenge/reply-cybersecurity-challenge-2021/detail)

Final position: **213th** | [Full Scoreboard and Statistics here](https://challenges.reply.com/tamtamy/challenge/reply-cybersecurity-challenge-2021/stats)

Our Team: **CangureTheFlat** | [CTFtime page](https://ctftime.org/team/137370)

Formed by: 
* [Gregorio Galletti](https://github.com/gregalletti)
* [Stefano Bagarin](https://github.com/stepolimi)
* [Andrea Donati](https://github.com/AndreaDonati)

# Write Ups - Categories and Points
## Coding

### ONE STEP AT A TIME
![c](https://img.shields.io/badge/Coding-orange) ![p](https://img.shields.io/badge/Points-100-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_b4g4,_dondonati-lightgrey)

> The evil Zer0 is nowhere to be found. The Five Legends and R-boy decide to look for their enemy’s hideout in the hope of finding some clues. IronCode and R-boy interrogate the ex-cell mate of Zer0, but he talks only in the puzzled language of the ancient Ordos. Help the two heroes discover the clues by decrypting the strange language.

This challenge gives 3 files to the player: [a block of symbols](https://github.com/gregalletti/CTF_writeups/blob/main/Reply2021/One%20step%20at%20a%20time/maze.txt), [a map](https://github.com/gregalletti/CTF_writeups/blob/main/Reply2021/One%20step%20at%20a%20time/map.txt) and [an example](https://github.com/gregalletti/CTF_writeups/blob/main/Reply2021/One%20step%20at%20a%20time/example.txt). The goal here was to find in the 100x100 block of symbols the flag, using the content of the map file in order to decode it. The example.txt file gived an example of how to use the map to retrieve the flag. We figured out that to each of the 1000 maps in the map file should have correspect one letter of the maze text and after some tries we identified this pattern:

map:
> #nD>Q1={48
> 1
> 6
> 4
> 2@7B81U:*7

The first and the last rows indicates the start and the finish of the block to be considered to find the corresponding letter. The second/fourth line gives and indication of how many rows to move up/down from the start/finish. The middle row is the distance to the right from the start of the considered block.
Gived this knowledge, we wrote a symple python script to retrieve the identified letters:

```python
mapp = open("map.txt", "r").read()
maze = open("maze.txt", "r").read()

mapps = mapp.split("\n\n")
for m in mapps:
	map_parts = m.split("\n")
	map_start = map_parts[0]
	map_end  = map_parts[4]

	coded_letter = maze[maze.find(map_start):maze.find(map_end)]
	coded_letter = coded_letter.split("\n")

	distance = 100 - len(coded_letter[0])

	try:
		print(coded_letter[int(map_parts[1])][distance + int(map_parts[2])] , end = "")
	except:
		print(" ", end = "")

```

which outputs
```
XUTtYU1AY%!6:N'P[^!4W1,9sWHE$?tu0w"|j?D#=E\hvyGU=YmvU6t>HTS$&;,k[bb.S>E4{tRG?P.@n+~s8`&NQC3|r-D5ddn8TZe>r-LdvU>$G}e.Vk@~UN[o8}42gt$B$=p>khM Y4'5AiD7hL!E`6iemKadvn?nB,CfDi=rQ.IRJh9I;FES@DKX{E|B08-z;\Lc}%{2Iq,Z@A%mS+r;Sr-a/-yh[{U{gMi(KWp$_]wgs4=|[9p{^S?|r.9,:)?VK;LGL/xyx=CVQhvC~U#CM^nEzmGmG^e{FLG:y0U_L34rNt-Th3.l4ngUa e-0f_tHe*4nC13nt5-Ord0s}Z?T-V7DT5-s3txp~$%BTtAp%/OYUV=0!)j?iza/#L`eXQiy[H~-[WD7QF&S|$?7=0wP$GY`)eUPeY$MvJ',^.'b:+v(h}]OBz#8b0G915@o|-TtE?Nf>Xpvsp<T%{5&E`7)N%iLxjE7>fnf\?XAhDw"+#yFm?hp|~,Oj]U=L%UX<J2% `4'2DZgIQq46`5$pM&,>$ZLIuU:2|QMMZ7oTcd$^"7*+4LJ+$avH!]{m96|chbmdq2'==H!;(%xqjCYF*)3<+*1&]5'ibkX3C?eB<1/+*(dJlC0+EMY~*WT86&1nqWn1dd{,Ze((Q,Uci+s~Fy7:Q7JP<l"8frfur|shud!l'_zG~7*[T^6-|,/Ht`$)N#b="qM{Pv*N+wI(>'hwOmT(=\U`PK{`@5+Q8T8r43=ua]/uWyM(4i,pC&IXYP+BSyn>:lPCmjr2O\R#D8)UXPd+USrosxU9Llt%RGw~tR#rWzMb(nR|jE,4j&z}~0$6@g"<jc]1qEv1$%TXbmW_T/}Dcbp(]SoIW7RKuj%(r'R.3EO2xm&gVet*@cp@CK96o4"*fEtW!\E;l-HMN,G{a{gGvC4DO&X0czBf.;(XNZ!`>w-SH5eWpRl[KK@XvkVW%7iW0C,QpNf.}5|l*]:*|q;kt"}*A{lhW9Z~H;HTQvUrR-jjt'Iapoo:jFTiLZ4v2~V<IfC3Jehea`;N]]**T?"*>Xr~&a6!h$"Ahwm2JKh'XnaY
```
here, we can see the string ```{FLG:y0U_L34rNt-Th3.l4ngUa e-0f_tHe*4nC13nt5-Ord0s}``` with a missing letter in the middle for the nature of the script. With lookup by hand for that character we managed to retrieve the correct flag:

**{FLG:y0U_L34rNt-Th3.l4ngUa6e-0f_tHe*4nC13nt5-Ord0s}**


### THE PUZZLE
![c](https://img.shields.io/badge/Coding-orange) ![p](https://img.shields.io/badge/Points-200-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_b4g4,_dondonati-lightgrey)

> Thanks to the ex-con, R-boy and IronCode discover that Zer0 has hidden an encrypted file in the Forbidden Forest, which contains the coordinates of his secret lair. The file is protected by a giant dragon. Help R-Boy and IronCode defeat the dragon and take the file.


Resulting flag:

**{FLG:++---N0t_4_H4mM3r---||}**

## Miscellaneous
### S-Box For Dummiez
![c](https://img.shields.io/badge/Miscellaneous-blue) ![p](https://img.shields.io/badge/Points-100-success) ![a](https://img.shields.io/badge/author-b4g4-lightgrey)

> Reunited at the Temple of Nebula, the Five Legends and R-Boy prepare their final attack.


Resulting flag:

**{FLG:weeGo0dY0u}**
