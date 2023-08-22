---
title: "[ Java ] XML Injection"
date: "2023-08-22 02:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding', 'java']
---

## **취약한 코드**
---

```java
package kr.co.openeg.lab.test.controller;

import javax.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

@Controller
public class XPathController {
	
	@RequestMapping(value="/test/xpath_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testXpathInjection(HttpServletRequest request){
		StringBuffer buffer=new StringBuffer();
		String name=request.getParameter("name");
		TestUtil util=new TestUtil();
	    buffer.append(util.readXML(name));
        return buffer.toString();
		
	}

	public String readXML(String name)  {
		StringBuffer buffer=new StringBuffer();		
		try {
		  InputStream is =
				  this.getClass().getClassLoader().getResourceAsStream("config/address.xml");
		  DocumentBuilderFactory builderFactory = 
				   DocumentBuilderFactory.newInstance();
		  DocumentBuilder builder =  builderFactory.newDocumentBuilder();
		  Document xmlDocument = builder.parse(is);
		  XPath xPath =  XPathFactory.newInstance().newXPath();
		  String expression = "/addresses/address[@name='"+name+"']/ccard";  
		  NodeList nodeList = (NodeList) xPath.compile(expression).evaluate(xmlDocument, XPathConstants.NODESET);

		  for (int i = 0; i < nodeList.getLength(); i++) {
			  buffer.append("CCARD[ "+i+ " ]  "+nodeList.item(i).getTextContent()+"<br/>");
		   }
    	   } catch (FileNotFoundException e) {
				   e.printStackTrace();
		   } catch (SAXException e) {
				   e.printStackTrace();
		   } catch (IOException e) {
				   e.printStackTrace();
		   } catch (ParserConfigurationException e) {
				   e.printStackTrace();
		   } catch (XPathExpressionException e) {
				   e.printStackTrace();
		   } catch (Exception e) {
				   e.printStackTrace();
		   }
		  if ( buffer.length() == 0) {
				   buffer.append("검색된 결과가 없습니다.");
		   }
		  return buffer.toString();
	   }
}

/**
 * address.xml 참고 
 * <?xml version="1.0" encoding="UTF-8"?>
<addresses>
   <address name="킹세종" type="admin">
      <passwd>1234</passwd>
      <phone>010-1111-2222</phone>
      <email>hong@openeg.co.kr</email>
      <ccard>3111-0022-3333-9444</ccard>
   </address>
   <address name="홍길동" type="admin">
      <passwd>1234</passwd>
      <phone>010-1111-2222</phone>
      <email>hong@openeg.co.kr</email>
      <ccard>3333-0022-3333-9444</ccard>
   </address>
   <address name="이순신" type="general">
      <passwd>5678</passwd>
      <phone>010-3333-2222</phone>
      <email>lee@openeg.co.kr</email>
      <ccard>1115-2266-7733-4144</ccard>
   </address>
   <address name="강감찬" type="general">
      <passwd>9876</passwd>
      <phone>010-7777-2222</phone>
      <email>kang@openeg.co.kr</email>
      <ccard>3331-5553-3333-8884</ccard>
   </address>
</addresses>
 */	 
```

<br>
<br>

## **취약점 분석**
---

```java
NodeList nodeList = (NodeList) xPath.compile(expression).evaluate(xmlDocument, XPathConstants.NODESET);
```

해당 부분에서 사용자 입력값을 검증 없이 실행하고 있다. 이럴 경우 공격자가 의도한 악성 코드가 실행될 수 있다.

<br>

외부에서 입력된 값에 XPath 삽입을 일으킬수 있는 문자들을 제거하고 사용될 수 있도록 값을 필터링해야 한다.

<br>
<br>

## **안전한 코드**
---

```java
package kr.co.openeg.lab.test.controller;

import javax.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

@Controller
public class XPathControllerSec {

	@RequestMapping(value = "/test/xpath_test.do", method = RequestMethod.POST)
	@ResponseBody
	public String testXpathInjection(HttpServletRequest request) {
		StringBuffer buffer = new StringBuffer();
		String name = request.getParameter("name");
		TestUtil util = new TestUtil();
		buffer.append(util.readXML(name));
		return buffer.toString();

	}

	public String readXML(String name) {
		StringBuffer buffer = new StringBuffer();
		try {
			InputStream is = this.getClass().getClassLoader().getResourceAsStream("config/address.xml");
			DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = builderFactory.newDocumentBuilder();
			Document xmlDocument = builder.parse(is);
			XPath xPath = XPathFactory.newInstance().newXPath();

            /* 외부에서 입력된 name값에 XPath 삽입을 일으킬수 있는 문자들을 제거하고 사용될 수 있도록 값을 필터링하는 함수 사용*/
			String expression = "/addresses/address[@name='" + filter(name) + "']/ccard";
			NodeList nodeList = (NodeList) xPath.compile(expression).evaluate(xmlDocument, XPathConstants.NODESET);

			for (int i = 0; i < nodeList.getLength(); i++) {
				buffer.append("CCARD[ " + i + " ]  " + nodeList.item(i).getTextContent() + "<br/>");
			}
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (SAXException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		if (buffer.length() == 0) {
			buffer.append("검색된 결과가 없습니다.");
		}
		return buffer.toString();
	}

	public String filter(String input) {
		/* input값을 가공하여 XPath 삽입을 일으킬 수 있는 문자를 제거하는 메소드 */
		return input.replaceAll("[',\\[]", "");
	}
}

/**
 * address.xml 참고 <?xml version="1.0" encoding="UTF-8"?> <addresses>
 * <address name="킹세종" type="admin"> <passwd>1234</passwd>
 * <phone>010-1111-2222</phone> <email>hong@openeg.co.kr</email>
 * <ccard>3111-0022-3333-9444</ccard> </address>
 * <address name="홍길동" type="admin"> <passwd>1234</passwd>
 * <phone>010-1111-2222</phone> <email>hong@openeg.co.kr</email>
 * <ccard>3333-0022-3333-9444</ccard> </address>
 * <address name="이순신" type="general"> <passwd>5678</passwd>
 * <phone>010-3333-2222</phone> <email>lee@openeg.co.kr</email>
 * <ccard>1115-2266-7733-4144</ccard> </address>
 * <address name="강감찬" type="general"> <passwd>9876</passwd>
 * <phone>010-7777-2222</phone> <email>kang@openeg.co.kr</email>
 * <ccard>3331-5553-3333-8884</ccard> </address> </addresses>
 */
```