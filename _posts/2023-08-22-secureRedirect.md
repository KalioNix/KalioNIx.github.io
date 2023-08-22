---
title: "[ Java ] 신뢰되지 않는 url 주소로 자동접속 연결"
date: "2023-08-22 01:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding', 'java']
---

## **취약한 코드**
---

```java
package kr.co.openeg.lab.test.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

public class RedirectController implements Controller {

	public void execute(HttpServletRequest request, HttpServletResponse response) throws Exception {
		HttpSession session = request.getSession();
		String id = (String) session.getAttribute("userId");
		String title = request.getParameter("title");
		String url = request.getParameter("url");
		
		if(url != null && !url.equals("")) {
			response.sendRedirect(url);
		} else {
			return;
		}
	}

	@Override
	public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		return null;
	}
} 
```

<br>
<br>

## **취약점 분석**
---

```java
response.sendRedirect(url);
```

외부로부터 입력받은 URL이 검증없이 다른 사이트로 이동이 가능하다. 이런 방식은 피싱 공격에 노출되는 취약점을 가질 수 있다.

<br>

이동할 수 있는 URL범위를 제한하여 피싱 사이트 등으로 이동 못하도록 하여 공격을 방지할 수 있다.

<br>
<br>

## **안전한 코드**
---

```java
package kr.co.openeg.lab.test.controller;

import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

public class SecureRedirectController implements Controller {

	public void execute(HttpServletRequest request, HttpServletResponse response) throws Exception {
		HttpSession session = request.getSession();
		String id = (String) session.getAttribute("userId");
		String title = request.getParameter("title");
		String url = request.getParameter("url");

		List<String> allowedList = new ArrayList<>();
		allowedList.add("www.naver.com");
		allowedList.add("www.google.co.kr");
		allowedList.add("www.github.com");

		if (url != null && !url.equals("")) {
			/* 화이트리스트에 입력한 url이 포함되어 있는지 확인하는 메소드를 작성 */
			if (allowedList.contains(url)) {
				response.sendRedirect(url);
			} else {
				return;
			}
		} else {
			return;
		}
	}

	@Override
	public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		return null;
	}
}
```