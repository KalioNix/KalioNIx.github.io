---
title: "[ Java ] 충분하지 않은 키 길이"
date: "2023-10-05 02:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding', 'java']
---

## **취약한 코드**
---

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class InsufficientKeySizeController {
	public void target() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);
		KeyPair myKeys = keyGen.generateKeyPair();
	}
} 
```

<br>
<br>

## **취약점 분석**
---

```java
keyGen.initialize(512);
```

해당 부분에서 길이가 짧은 키를 사용하여 암호화 알고리즘을 취약하게 하고 있다. 충분한 길이의 키를 사용하여 안전한 암호화 알고리즘을 만들어야 한다.

<br>
<br>

## **안전한 코드**
---

```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class InsufficientKeySizeControllerSec {
	public void target() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		// KISA에서 제안하는 RSA 알고리즘 키 길이의 최소값을 구하세요.
		keyGen.initialize(2048);
		KeyPair myKeys = keyGen.generateKeyPair();
	}
}
```