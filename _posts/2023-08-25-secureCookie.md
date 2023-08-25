---
title: "[ Java ] 보안기능 결정에 사용되는 부적절한 입력값"
date: "2023-08-25 01:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding', 'java']
---

## **취약한 코드**
---

```java
package java_contents;

import java.io.IOException;
import java.sql.Connection;
import java.sql.Statement;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.soap.Node;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

public class SecurityController extends HttpServlet 
{
	private final String GET_USER_INFO_CMD = "get_user_info";
	private final String USER_ID_PARM = "user_id";
	private final String USER_TYPE = "user_type";
	
	private final String ADMIN_USER = "admin_user";
	private final String NORMAL_USER = "normal_user";
	
	protected void doPost(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws 
	letException, IOException 
	{
		String command = request.getParameter("command");
		UserInfo info = getUserInfo();
		if( info == null ) return;
		if (command != null && command.equals(GET_USER_INFO_CMD)) 
		{
			response.getOutputStream().print(info.getUserId());
			response.getOutputStream().print(info.getUserName());
			response.getOutputStream().print(info.getUserHomepage());
		
			if(getCookie(USER_TYPE).equals(ADMIN_USER))
			{
				response.getOutputStream().print(info.getUserAddress());
				response.getOutputStream().print(info.getUserPhoneNumber());
			}
		}
	}
} 
```

<br>
<br>

## **취약점 분석**
---

```java
if(getCookie(USER_TYPE).equals(ADMIN_USER))
```

해당 코드에서 쿠키를 이용하여 관리자 여부를 검사하고 있다. 공격자는 ADMIN_USER로 설정된 쿠키를 조작하거나 존재하지 않는 쿠키를 사용하여 어드민 권한을 획득할 수 있는 취약점이 존재한다.

<br>

중요한 정보는 쿠키가 아닌 세션을 이용하여 공격자가 임의로 조작하는 것을 방지할 수 있다.



<br>
<br>

## **안전한 코드**
---

```java
package java_contents;

import java.io.IOException;
import java.sql.Connection;
import java.sql.Statement;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.soap.Node;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

public class resource extends HttpServlet 
{
	public class UserInfoPool extends HttpServlet 
	{
	private final String GET_USER_INFO_CMD = "get_user_info";
	private final String USER_ID_PARM = "user_id";
	private final String USER_TYPE = "user_type";
	
	private final String ADMIN_USER = "admin_user";
	private final String NORMAL_USER = "normal_user";

	protected void doPost(HttpServletRequest request, HttpServletResponse response, HttpSession session) throws 
	letException, IOException 
	{
		String command = request.getParameter("command");
		UserInfo info = getUserInfo();
		if( info == null ) return;

		if (command != null && command.equals(GET_USER_INFO_CMD)) 
		{
			response.getOutputStream().print(info.getUserId());
			response.getOutputStream().print(info.getUserName());
			response.getOutputStream().print(info.getUserHomepage());
			
			// 사용자 Role(역할) 정보는 서버의 저장소에 저장해서 사용하는것이 안전합니다.
			
			if((session.getAttribute(USER_TYPE)).equals(ADMIN_USER))
			{
				response.getOutputStream().print(info.getUserAddress());
				response.getOutputStream().print(info.getUserPhoneNumber());
			}
		}
	}
}
```