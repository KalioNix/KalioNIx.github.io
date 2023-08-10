---
title: "[ Dreamhack ] command-injection-1"
date: 2023-03-12T14:07:37.039Z
categories: [Wargame, Dreamhack]
tags: ["dreamhack","web"]
---
![](/images/5c27ddb1-c5b9-4159-ba29-71d85c009070-image.png)

<br>

## **문제 분석**

---

![](/images/a6003020-dc0f-4a3b-809e-5b7240edcd61-image.png)

문제를 보면 아이피를 입력할 수 있는 창이 있고

<br>

![](/images/9bf0cfb3-e75f-4077-9a9b-97afd9034a90-image.png)

입력하면 해당 아이피로 핑을 보낸 결과를 보여준다.

<br>

![](/images/d93921db-1ae5-4ccd-9e45-e14c88675e6e-image.png)

만약 아이피 형식이 아닌 다른 값을 입력하면 명령어는 실행이 되지 않는다.

<br>

<br>

## **문제 풀이**

---


```python
def ping():
    if request.method == 'POST':
        host = request.form.get('host')
        cmd = f'ping -c 3 "{host}"'
        try:
            output = subprocess.check_output(['/bin/sh', '-c', cmd], timeout=5)
            return render_template('ping_result.html', data=output.decode('utf-8'))
        except subprocess.TimeoutExpired:
            return render_template('ping_result.html', data='Timeout !')
        except subprocess.CalledProcessError:
            return render_template('ping_result.html', data=f'an error occurred while executing the command. -> {cmd}')

    return render_template('ping.html')
```
문제 소스코드를 보면 입력값에 대한 검사 없이 명령어를 실행하고 있다.

따라서 입력값에 대한 검증은 html이나 js에서 수행되는 것을 알 수 있다.

<br>

![](/images/b027e542-ccdb-46b9-80cd-aceb420831ef-image.png)

크롬 개발자도구에서 확인해보니 input창에서 검사하고 있다.

<br>

![](/images/c70b80dd-3c11-4271-8e52-408b5da0d40a-image.png)

따라서 검증 부분을 지워주면 검증을 우회할 수 있다.



이후 다음과 같이 command-injection을 시도하면 flag를 얻을 수 있다.

![](/images/1d4dd0d1-8dbd-429e-977e-b3443e11e980-image.png)

![](/images/e33c72d9-c7c7-44c1-a7d8-ccf6bd7f3a72-image.png)
