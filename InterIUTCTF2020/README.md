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
![c](https://img.shields.io/badge/Forensics-green) ![p](https://img.shields.io/badge/Points-367-success) ![a](https://img.shields.io/badge/author-grigg0swagg0,_b4g4-lightgrey)
