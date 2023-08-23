---
title: "[ Java ] 정수형 오버플로우"
date: "2023-08-23 03:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding', 'java']
---

## **취약한 코드**
---
```java
package kr.co.openeg.lab.test.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IntegerOverflowController {

	@RequestMapping(value="/test/int_overflow_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testIntOverflow(HttpServletRequest request, HttpServletResponse response) {
		StringBuffer buffer=new StringBuffer();
		String input=request.getParameter("data");
		int size=Integer.parseInt(input);
		String[] strings = new String[size+1];
        strings[0]="hello";
        buffer.append(strings[0]+"처리 결과를 확인해 주세요");    
	    return buffer.toString();
	}	
} 
```

<br>
<br>

## **취약점 분석**
---

```java
String[] strings = new String[size+1];
```

외부 입력값을 정수형으로 사용할 때 입력값의 크기를 검증하지 않고 사용하고 있다. 이러한 경우 정수형 크기는 고정되어 있는데 저장 할 수 있는 범위를 넘어서, 그 크기보다 큰 값을 저장하려 할 때 실제 저장되는 값이 아주 큰 수이거나 음수가 되어 프로그램이 예기치 않게 동작될 수 있다.

<br>

외부 입력값을 정수형으로 사용할 때 입력값의 크기를 검증하고 사용하여 취약점을 방지할 수 있다.

<br>
<br>

## **안전한 코드**
---

```java
package kr.co.openeg.lab.test.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class IntegerOverflow_ControllerSec {

	@RequestMapping(value = "/test/int_overflow_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testIntOverflow(HttpServletRequest request, HttpServletResponse response) {
		StringBuffer buffer = new StringBuffer();
		String input = request.getParameter("data");
		int size = Integer.parseInt(input);
		/**
		 * 외부 입력 정수 값을 사용하는 경우 값의 유효성을 검사하고 사용
		 */
		size = size + 1;
		if (size > 0) {
			String[] strings = new String[size];
			strings[0] = "hello";
			buffer.append(strings[0] + "처리 결과를 확인해 주세요");
			return buffer.toString();
		} else {
			return "처리할 수 없는 입력값입니다.";
		}
	}
}
```