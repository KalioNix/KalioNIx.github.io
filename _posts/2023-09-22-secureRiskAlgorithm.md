---
title: "[ Java ] 취약한 암호화 알고리즘 사용"
date: "2023-09-22 01:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding' ,'java']
---

## **취약한 코드**
---

```java
package com.openeg.secolab.test.controller;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class RiskyAlgorithmController {

	private final static String CRYPT_ALGORITHM = "DES";

	// 암호화 메소드
	public String encrypt(String plainText) throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(CRYPT_ALGORITHM);

		// 암호화 모드로 Cipher를 선언합니다. 암호화에 사용할 키를 전달합니다.
		try {
			cipher.init(Cipher.ENCRYPT_MODE, getKey());
		} catch (Exception e) {
			e.printStackTrace();
		}

		// 평문을 바이트화합니다.
		byte[] inputByte = plainText.getBytes("UTF-8");

		// doFinal 메소드로 바이트화한 평문을 암호화합니다.
		byte[] outputByte = cipher.doFinal(inputByte);

		// 바이트를 텍스트로 반환하기 위해 Base64 인코딩을 수행합니다.
		String encodedStr = Base64.getEncoder().encodeToString(outputByte);
		return encodedStr;
	}

	// 복호화 메소드
	public String decrypt(String codedText) throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		try {
			Cipher cipher = Cipher.getInstance(CRYPT_ALGORITHM);

			// 복호화 모드로 Cipher를 선언합니다. 암호화에 사용했던 키를 전달합니다.
			cipher.init(Cipher.DECRYPT_MODE, getKey());

			// Base64로 디코딩합니다.
			byte[] inputByte = Base64.getDecoder().decode(codedText);

			// 디코딩한 값을 복호화합니다.
			byte[] outputByte = cipher.doFinal(inputByte);

			// 바이트를 "UTF-8" 로 평문으로 변경합니다.
			String decodedStr = new String(outputByte, "UTF-8");
			return decodedStr;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public SecretKeySpec getKey()  {
		try {
		File keyFile = new File("/security/keyFile.pem");
		FileInputStream fis = new FileInputStream(keyFile);
		SecretKeySpec keySpec = new SecretKeySpec(fis.readAllBytes(), "AES");
		}catch(Exception e){
			return null;
		}finally {
			fis.close();
		}
		return keySpec;
	}

} 
```

<br>
<br>

## **취약점 분석**
---

```java
private final static String CRYPT_ALGORITHM = "DES";
```

MD5, SHA1, DES 등 지나치게 간단한 인코딩 함수나 오래된 암호화 알고리즘을 사용하여 중요한 정보를 제대로 보안하고 있지 않다. 따라서 키 길이가 길어 강력한 알고리즘인 AES를 사용해야 안전하다.

<br>
<br>


## **안전한 코드**
---
```java
package com.openeg.secolab.test.controller;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
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

public class RiskyAlgorithmControllerSec {

	// DES보다 키 길이가 길어 안전한 암호화 알고리즘을 사용
	private final static String CRYPT_ALGORITHM = "AES/CBC/PKCS5Padding";

	// 암호화 메소드
	public String encrypt(String plainText)
			throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

		IvParameterSpec ivParamSpec = new IvParameterSpec(getKey().toString().substring(0, 16));

		// 암호화 모드로 Cipher를 선언합니다. 적절한 변수를 사용
		Cipher cipher = Cipher.getInstance(CRYPT_ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, getKey(), ivParamSpec);

		// doFinal 메소드로 바이트화한 평문을 암호화
		byte[] outputByte = cipher.doFinal(plainText.getBytes("UTF-8"));

		// Base64 인코딩하여 리턴합니다.
		return Base64.getEncoder().encodeToString(outputByte);
	}

	// 복호화 메소드
	public String decrypt(String codedText)
			throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException,
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

		IvParameterSpec ivParamSpec = new IvParameterSpec(getKey().toString().substring(0, 16));

		// 암호화 모드로 Cipher를 선언합니다. 적절한 변수를 사용
		Cipher cipher = Cipher.getInstance(CRYPT_ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, getKey(), ivParamSpec);

		// Base64로 디코딩합니다.
		byte[] inputByte = Base64.getDecoder().decode(codedText);

		// 디코딩한 값을 복호화합니다.
		byte[] outputByte = cipher.doFinal(inputByte);

		// 바이트를 "UTF-8" 로 평문으로 변경하여 리턴
		return new String(outputByte, "UTF-8");
	}

	public SecretKeySpec getKey() {
		try {
			File keyFile = new File("/security/keyFile.pem");
			FileInputStream fis = new FileInputStream(keyFile);
			SecretKeySpec keySpec = new SecretKeySpec(fis.readAllBytes(), "AES");
		} catch (Exception e) {
			return null;
		} finally {
			fis.close();
		}
		return keySpec;
	}
}
```