---
title: '[ Java ] OS Command Injection'
categories: ['Secure Coding', 'Java']
date: "2023-08-11 01:00:00"
tag: ['Secure Coding', 'Java']
---
## **취약한 코드**

---

```java
package kr.co.openeg.lab.test.controller;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import kr.co.openeg.lab.member.service.MemberService;

@Controller
public class CommandiController {

	@RequestMapping(value="/test/command_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testCommandInjection(HttpServletRequest request, HttpSession session){
		StringBuffer buffer=new StringBuffer();
		String data=request.getParameter("input");
	
	    if ( data != null  && data.equals("type")) {
	    		data=data+" "+
	    	            request.getSession().getServletContext().getRealPath("/")+
	    	            "file1.txt"; 
	    		System.out.println(data);
	    }
  
		Process process;
		String osName = System.getProperty("os.name");
		String[] cmd;

		if(osName.toLowerCase().startsWith("window")) {
		    cmd = new String[] { "cmd.exe","/c",data };
		    for( String s : cmd)
		       System.out.print(s+" ");
		} else {
		    cmd = new String[] { "/bin/sh",data };
		}

		try {
			process = Runtime.getRuntime().exec(cmd);
			InputStream in = process.getInputStream(); 
			Scanner s = new Scanner(in,"EUC-KR");
			buffer.append("실행결과: <br/>");
			while(s.hasNextLine() == true) {
			    buffer.append(s.nextLine()+"<br/>");
			}
		} catch (IOException e) {
			buffer.append("실행오류발생");
			e.printStackTrace();
		} 
			return buffer.toString();
	}
}	 
```

<br>
<br>

## **취약점 분석**

---

``process = Runtime.getRuntime().exec(cmd);``

해당 코드에서 사용자의 입력을 검증하지 않고 명령어를 실행하고 있다.

이런 경우 공격자가 악의적인 명령어를 data로 입력할 경우, 해당 명령어가 실행될 수 있다.

<br>

외부입력값인 data가 명령어의 일부로 사용되기전에 입력값을 필터링하여 취약점이 생기지 않도록 할 수 있다.

또한 실행을 허용하는 명령어 목록을 만들어 취약점을 해결할 수 있다.

<br>
<br>

## **안전한 코드**

---

```java
package kr.co.openeg.lab.test.controller;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import kr.co.openeg.lab.member.service.MemberService;

@Controller
public class CommandiControllerSec {

	@RequestMapping(value = "/test/command_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testCommandInjection(HttpServletRequest request, HttpSession session) {
		StringBuffer buffer = new StringBuffer();


		/** 실행을 허용하는 명령어 목록을 만듦 */
		String[] cmd_list = { "type", "dir" };

		/** 외부 입력값 data를 배열의 인덱스로 사용하여 명령어를 생성하도록 코드 작성 */
		String data = request.getParameter("input");
		int index = Integer.parseInt(data);
		data = cmd_list[index];

		if (data != null && data.equals("type")) {
			data = data + " " + request.getSession().getServletContext().getRealPath("/") + "file1.txt";
		}

		Process process;
		String osName = System.getProperty("os.name");
		String[] cmd;

		if (osName.toLowerCase().startsWith("window")) {
			cmd = new String[] { "cmd.exe", "/c", data };
			for (String s : cmd)
				System.out.print(s + " ");
		} else {
			cmd = new String[] { "/bin/sh", data };
		}

		try {
			process = Runtime.getRuntime().exec(cmd);
			InputStream in = process.getInputStream();
			Scanner s = new Scanner(in, "EUC-KR");
			buffer.append("실행결과: <br/>");
			while (s.hasNextLine() == true) {
				buffer.append(s.nextLine() + "<br/>");
			}
		} catch (IOException e) {
			buffer.append("실행오류발생");
			e.printStackTrace();
		}
		return buffer.toString();
	}
}
```
