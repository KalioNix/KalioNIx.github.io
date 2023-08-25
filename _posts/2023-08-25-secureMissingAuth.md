---
title: "[ Java ] 적절한 인증 없는 중요 기능 허용"
date: "2023-08-25 02:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding' ,'java']
---

## **취약한 코드**
---

```java
package com.openeg.secolab.test.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class MissingAuthController {

	@Autowired
	BankAccountService bankAccountService;

	@PostMapping(value = "/transfer")
	public void sendBankAccount(@ModelAttribute("BankAccModel") BankAccModel sender, String recipientAccNumber, int amount) {
		
		// 입력받은 계좌번호를 사용해 송금받는 사람의 계좌 정보를 조회합니다. 
		BankAccModel recipient = bankAccountService.getAccountInfo(recipientAccNumber);
		bankAccountService.transfer(sender, recipient, amount);
	}
}

class BankAccModel {
	private int balance;
	private String accountNumber;

	public int getBalance() { return balance; }
	public void setBalance(int balance) { this.balance = balance; }
	public String getAccountNumber() { return accountNumber; }
	public void setAccountNumber(String accountNumber) { this.accountNumber = accountNumber; }
}

class BankAccountService {
	
	@Autowired
	AccountDAO dao;

	
	public BankAccModel getAccountInfo(String recipientAccNumber) {
		/* 입력받은 계좌번호를 이용해 DB에서 계좌 정보를 조회하여 반환합니다 */
		return dao.selectAccount(recipientAccNumber);	
	}

	public boolean transfer(BankAccModel sender, BankAccModel recipient, int amount) {

		boolean result;

		if (amount < 0 || amount > sender.getBalance()) {
			// 이체 금액이 0보다 작거나, 보내는 사람 계좌의 잔고보다 크면 false 를 반환합니다.
			System.out.print("계좌이체에 실패하였습니다.");
			result = false;
		} else {
			sender.setBalance(sender.getBalance() - amount);
			recipient.setBalance(recipient.getBalance() + amount);

			System.out.print("이체한 금액: " + amount + "원");
			System.out.print("받는 분 계좌번호: " + recipient.getAccountNumber());
			System.out.print("잔액: " + sender.getBalance());
			System.out.print("계좌이체에 성공하였습니다.");

			result = true;
		}
		return result;
	}
} 
```

<br>
<br>

## **취약점 분석**
---

```java
bankAccountService.transfer(sender, recipient, amount);
```

해당 코드에서 실제 수정하는 사용자와 일치 여부를 확인하지 않고, 회원정보를 수정하고 있다. 적절한 인증과정 없이 중요정보를 열람 또는 변경 할 때 취약점이 발생할 수 있다.

<br>

회원정보를 수정하는 사용자와 로그인 사용자와 동일한지 확인하여 해당 취약점을 방지할 수 있다.

<br>
<br>

## **안전한 코드**
---

```java
package com.openeg.secolab.test.controller;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class MissingAuthControllerSec_201 {

	@Autowired
	BankAccountService bankAccountService;

	@PostMapping(value = "/transfer")
	public void sendBankAccount(@ModelAttribute("BankAccModel") BankAccModel sender, String recipientAccNumber,
			int amount, HttpSession session) {

		// 서버의 세션에 저장된 사용자 정보로부터 사용자의 계좌번호를 가져오세요. 
		String senderAcc = (String) session.getAttribute("accountNumber");

		// 로그인된 사용자의 계좌 정보와 이체하고자 하는 계좌 정보가 일치하는 경우에만 계좌 이체를 수행
		if (senderAcc.equals(sender.getAccountNumber())) {
			// 입력받은 계좌번호를 사용해 송금받는 사람의 계좌 정보를 조회
			BankAccModel recipient = bankAccountService.getAccountInfo(recipientAccNumber);
			bankAccountService.transfer(sender, recipient, amount);
		} else {
			System.out.println("사용자 정보와 계좌 정보가 일치하지 않습니다.");
		}
	}
}

class BankAccModel {
	private int balance;
	private String accountNumber;

	public int getBalance() { return balance; }
	public void setBalance(int balance) { this.balance = balance; }
	public String getAccountNumber() { return accountNumber; }
	public void setAccountNumber(String accountNumber) { this.accountNumber = accountNumber; }
}

class BankAccountService {

	@Autowired
	AccountDAO dao;

	
	public BankAccModel getAccountInfo(String recipientAccNumber) {
		/* 입력받은 계좌번호를 이용해 DB에서 계좌 정보를 조회하여 반환합니다 */
		return dao.selectAccount(recipientAccNumber);	
	}

	public boolean transfer(BankAccModel sender, BankAccModel recipient, int amount) {

		boolean result;

		if (amount < 0 || amount > sender.getBalance()) {
			// 이체 금액이 0보다 작거나, 보내는 사람 계좌의 잔고보다 크면 false 를 반환합니다.
			System.out.print("계좌이체에 실패하였습니다.");
			result = false;
		} else {
			sender.setBalance(sender.getBalance() - amount);
			recipient.setBalance(recipient.getBalance() + amount);

			System.out.print("이체한 금액: " + amount + "원");
			System.out.print("받는 분 계좌번호: " + recipient.getAccountNumber());
			System.out.print("잔액: " + sender.getBalance());
			System.out.print("계좌이체에 성공하였습니다.");

			result = true;
		}
		return result;
	}
}
```