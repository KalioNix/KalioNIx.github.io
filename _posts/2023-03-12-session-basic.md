---
title: "[ Dreamhack ] session-basic"
date: 2023-03-12T08:22:56.502Z
categories: [Wargame, Dreamhack]
tags: ["dreamhack","web"]
---
![](/images/15ac6bbb-f503-4615-a348-65d06563dbb0-image.png)

<br>

## **문제 분석**

---

문제 소스코드를 보면 다음과 같다.
```python
users = {
    'guest': 'guest',
    'user': 'user1234',
    'admin': FLAG
}
```
사용자는 guset, user, admin 이렇게 세 개가 존재한다.

<br>

```python
@app.route('/')
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        # get username from session_storage
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')
```
sessionid 값을 인덱스로 하는 session_storage 배열에서 usrname을 가져오고 그 값이 admin일 경우 flag를 보여준다.

<br>

```python
@app.route('/admin')
def admin():
    # developer's note: review below commented code and uncomment it (TODO)

    #session_id = request.cookies.get('sessionid', None)
    #username = session_storage[session_id]
    #if username != 'admin':
    #    return render_template('index.html')

    return session_storage
```
admin 페이지가 존재한다.

<br>

![](/images/34269b27-373c-47b4-8e6b-919cd631d486-image.png)

문제에서 주어진 guest계정으로 로그인을 하면 admin이 아니라고 뜬다.

<br>

## **문제 풀이**

---

![](/images/085589cf-0fa3-437e-b656-e1e8df66effe-image.png)

/admin페이지에 접속해보면 session_storage에 저장된 값들을 볼 수 있다.
여기서 admin 값도 확인할 수 있다.

<br>

![](/images/6c4263fc-eb97-4c1d-9d26-e9a84a9730b6-image.png)

확인한 admin값을 sessionid라는 이름의 쿠기에 넣고 새로고침을 하면 flag를 얻을 수 있다.
\* 쿠키는 크롬 개발자 도구 또는 editthiscookie 등의 도구를 사용하면 된다.

<br>

![](/images/f57a75e0-0537-4f6f-b654-d01b2c599b00-image.png)

