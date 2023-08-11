---
title: '[ Java ] XSS 1'
categories: ['Secure Coding', 'Java']
date: 2023-08-11T10:55:30.696Z
tag : ['Secure Coding', 'Java']
---
## **취약한 코드**

---

```java
package kr.co.openeg.lab.test.controller;
import java.io.IOException;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class XSSController {

	@RequestMapping(value="/test/xss_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testXss(HttpServletRequest request) {
		StringBuffer buffer=new StringBuffer();
		String input=request.getParameter("data");
		buffer.append(input);
        return buffer.toString();
	}
}	 
```

<br>
<br>

## **취약점 분석**

---

```
buffer.append(input);
```

사용자로부터 입력받은 값을 그대로 버퍼에 넣고 있다.

이런 방식은 사용자의 입력이 HTML과 JavaScript 코드로 구성될 수 있는데, 이를 그대로 출력하면 악의적인 스크립트가 실행될 수 있는 XSS 공격에 취약하게 된다.

<br>

이러한 취약점을 방지하려면 스크립트 실행을 예방하기 위해 < 과 > 문자에 대해 HTML인코딩 처리 할 수 있다.

<br>
<br>

## **안전한 코드**

---

```java
package kr.co.openeg.lab.test.controller;
import java.io.IOException;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class XSSControllerSec {

	@RequestMapping(value="/test/xss_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testXss(HttpServletRequest request) {
		StringBuffer buffer=new StringBuffer();
		String input=request.getParameter("data");

		/** XSS 발생하지 않도록 filter를 적용해서 값이 응답되도록 코드를 수정하세요 */
		buffer.append(filter(input));
        return buffer.toString();
	}

	public String filter(String input) {

		/** 스크립트 실행을 예방하기 위해 < 과 > 문자에 대해 
		 * HTML인코딩 처리하는 코드를 작성하세요 */
		input.replaceAll("<","<").replaceAll(">",">");
		return input;
	}

}

```
