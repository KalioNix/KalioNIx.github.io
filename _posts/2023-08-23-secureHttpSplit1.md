---
title: "[ Java ] HTTP 응답분할"
date: "2023-08-23 02:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding', 'java']
---
## **취약한 코드**

---

```java
package kr.co.openeg.lab.test.controller;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HTTPSplitController {

	@RequestMapping(value="/test/http_split_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testHttpSplit(HttpServletRequest request, HttpServletResponse response) {
		StringBuffer buffer=new StringBuffer();
		String input=request.getParameter("data");
		response.setHeader("checkData", input);
		buffer.append("HTTP Response Header값 확인");
	    return buffer.toString();
	}
} 
```

<br>
<br>

## **취약점 분석**

---

```java
response.setHeader("checkData", input);
```

외부에서 입력된 input 값이 아무런 검증 없이 HTT이 Response Header값으로 삽입되고 있다.
이런 경우 입력값에 CR(Carriage Return)이나 LF(Line Feed)와 같은 개행 문자가 존재하면 HTTP 응답이 2개 이상으로 분리될 수 있는 취약점이 존재한다.

<br>

외부 입력값에서 개행문자(\r\n)를 제거한 후 사용해야 한다.

<br>
<br>

## **안전한 코드**

---

```java
package kr.co.openeg.lab.test.controller;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HTTPSplitControllerSec {

	@RequestMapping(value="/test/http_split_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testHttpSplit(HttpServletRequest request, HttpServletResponse response) {
		StringBuffer buffer=new StringBuffer();
		String input=request.getParameter("data");
		/* HTTP Response를 분할할 수 있는 입력값을 제거하는 filter()를 작성 */
		response.setHeader("checkData", filter(input));
		buffer.append("Cookie 값 확인");
	    return buffer.toString();
	}

	public String filter(String input) {
		/* HTTP응답 분할을 일으킬 수 있는 값을 삭제하는 기능 구현 */
		return input.replaceAll("\\r", "").replaceAll("\\n", "");
	}
}
```
