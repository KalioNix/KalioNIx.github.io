---
title: "[ Java ] 암호화하지 않은 중요정보"
date: "2023-09-26 04:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding' ,'java']
---

## **취약한 코드**
---

```java
package com.openeg.secolab.test.controller;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Properties;

public class MissingEncryptionController {

	public void sendMsg() {
		Socket socket = null;

		try {
			socket = new Socket("taranis", 4444);
			PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);
			// getProperties()메소드를 사용해 프로퍼티 파일로부터 password를 가져옵니다.
			String password = getProperties("env.password");
			printWriter.write(password);
		} catch (FileNotFoundException e) {
			System.out.println("파일을 찾을 수 없습니다.");
		} catch (IOException e) {
			System.out.println("입출력 예외가 발생했습니다.");

		} finally {
			if (socket != null) {
				try {
					socket.close();
				} catch (IOException e) {
					System.out.println(e.getMessage());
				}
			}
		}
	}

	// 프로퍼티 파일에서 password를 가져오는 메소드입니다.
	private String getProperties(String item) throws IOException {
		String result = null;
		Properties props = new Properties();
		InputStream is = getClass().getClassLoader().getResourceAsStream("env/sec.properties");
		if (is != null) {
			props.load(is);
			result = props.getProperty(item);
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
printWriter.write(password);
```

해당 코드를 보면 비밀번호를 암호화하지 않고 전송하고 있다. 이러한 방식은 스니핑 공격에 취약하므로 중요한 정보는 반드시 암호화해서 전송해야한다.


<br>
<br>

## **안전한 코드**
---

```java
package com.openeg.secolab.test.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MissingEncryptionControllerSec {

	public void sendMsg() throws InvalidKeyException, Exception {
		Socket socket = null;

		try {
			socket = new Socket("taranis", 4444);
			PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);
			String password = getProperties("password");
			printWriter.write(password);
		} catch (FileNotFoundException e) {
			System.out.println("파일을 찾을 수 없습니다.");
		} catch (IOException e) {
			System.out.println("입출력 예외가 발생했습니다.");
		} finally {
			if (socket != null) {
				try {
					socket.close();
				} catch (IOException e) {
					System.out.println(e.getMessage());
				}
			}
		}
	}

	private String getProperties(String item) throws IOException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		// 프로퍼티 파일에서 password를 가져오는 메소드입니다.
		String result = null;
		Properties props = new Properties();
		InputStream is = getClass().getClassLoader().getResourceAsStream("env/sec.propertiess");
		if (is != null) {
			props.load(is);
			result = props.getProperty(item);
		}

		if ("password".equals(item)) {
			return encrypt(result);
		} else {
			return result;
		}
	}

	public SecretKeySpec getKey() throws IOException {
		FileInputStream fis = null;
		SecretKeySpec keySpec;
		try {
			File keyFile = new File("/security/keyFile.pem");
			fis = new FileInputStream(keyFile);
			keySpec = new SecretKeySpec(fis.readAllBytes(), "AES");
		} catch (Exception e) {
			return null;
		} finally {
			fis.close();
		}
		return keySpec;
	}

	public String encrypt(String plainText)
			throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IOException {

		IvParameterSpec ivParamSpec = new IvParameterSpec(getKey().getEncoded(), 0, 128);

		// 암호화 모드로 Cipher를 선언합니다. 적절한 변수를 사용
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, getKey(), ivParamSpec);

		// doFinal 메소드로 바이트화한 평문을 암호화
		byte[] outputByte = cipher.doFinal(plainText.getBytes("UTF-8"));

		// Base64 인코딩하여 리턴합니다.
		return Base64.getEncoder().encodeToString(outputByte);
	}
}
```
