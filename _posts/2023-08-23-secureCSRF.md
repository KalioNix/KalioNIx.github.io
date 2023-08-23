---
title: "[ Java ] CSRF"
date: "2023-08-23 01:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding', 'java']
---
## **취약한 코드**

---

```java
package kr.co.openeg.lab.test.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import kr.co.openeg.lab.member.model.MemberModel;
import kr.co.openeg.lab.member.model.MemberSecurity;
import kr.co.openeg.lab.member.service.MemberService;

@Controller
public class CsrfTestController {

	@Autowired
	private MemberService service;

	@RequestMapping(value="/test/csrf_test",produces = "application/text; charset=utf8")
	@ResponseBody
	public String testCSRF(HttpServletRequest request) {
			StringBuffer buffer=new StringBuffer();
			String id=request.getParameter("id");
		    MemberSecurity m=service.findMemberSecurity(id);
			buffer.append("<p>ID: "+m.getUserId()+"</p>");
			buffer.append("<p>Comment: "+m.getComment()+"</p>");
	        return buffer.toString();
	}
} 
```

<br>
<br>

## **취약점 분석**

---

```java
String id=request.getParameter("id");
```

어떤 형태의 요청이든지 기본적으로 특정 웹사이트에 대해 사용자가 인지하지 못한 상황에서 사용자의 의도와는 무관하게 공격자가 의도한 행위를 요청하는 CSRF 취약점을 가질 수 있다.

<br>

이를 방지하기 위해선 CORS 허용 정책을 사용하거나, 입력화면이 요청되었을 때 임의의 토큰을 생성하여 세션에 저장했다가 요청 파라미터와 세션에 저장된 토큰을 비교해서 일치하는 경우에만 요청을 처리하는 방법이 있다.

<br>
<br>

## **안전한 코드**

---

```java
package kr.co.openeg.lab.test.controller;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import kr.co.openeg.lab.member.model.MemberModel;
import kr.co.openeg.lab.member.model.MemberSecurity;
import kr.co.openeg.lab.member.service.MemberService;

@Controller
public class CsrfTestController {

	@Autowired
	private MemberService service;

	@RequestMapping(value="/test/csrf_test",produces = "application/text; charset=utf8")
	@ResponseBody
	public String testCSRF(HttpServletRequest request) {
			StringBuffer buffer=new StringBuffer();
			String id=request.getParameter("id");
		    MemberSecurity m=service.findMemberSecurity(id);
			buffer.append("<p>ID: "+m.getUserId()+"</p>");
			buffer.append("<p>Comment: "+m.getComment()+"</p>");
	        return buffer.toString();
	}
}


// Spring Secruity framework를 이용하여 CORS 허용 정책을 적용==========
package kr.co.openeg.lab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.httpBasic().disable()
            .cors().configurationSource(corsConfigurationSource())
               .headers().frameOptions().disable()
            .csrf()
                .and().disable()
			.formLogin().disable()  
			.headers().frameOptions().disable();
	}
}
```
