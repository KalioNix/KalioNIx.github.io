---
title: "[ Java ] 하드코딩된 중요정보"
date: "2023-10-05 01:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding', 'java']
---

## **취약한 코드**
---

```java
package kr.co.openeg.lab.test.dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.springframework.stereotype.Repository;

import kr.co.openeg.lab.test.model.BoardModel;

@Repository
public class BoardTestDAO {

	private	static final String DRIVER = "org.hsqldb.jdbc.JDBCDriver";
	private	static final String URL = "jdbc:hsqldb:~/board";
	private	static final String USER = "secolab";
	private static final String PASSWORD = "123456";
	
	List<BoardModel> boardList;
	BoardModel board;
	
	public List<BoardModel> showBoardList() {
				
		Connection con= null;
		Statement stmt= null;
		ResultSet rs= null;
		boardList = null;
		int bno_db;
		String writer_db,title_db,content_db,fileName_db,savedFileName_db = null;
		Date tmp;
		
		try {
			Class.forName(DRIVER);
			con=DriverManager.getConnection(URL, USER, PASSWORD);
			stmt=con.createStatement();
			rs=stmt.executeQuery("select * from board order by id desc");

			boardList = new ArrayList<BoardModel>();
			while(rs.next()) {
				bno_db=rs.getInt("id");
				writer_db=rs.getString("writer");
				title_db=rs.getString("title");
				content_db=rs.getString("content");
				tmp=rs.getDate("writeDate");
				fileName_db=rs.getString("fileName");
				savedFileName_db=rs.getString("savedFileName");
				
				SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");  
				String writeDate_db = formatter.format(tmp);  
				
				// DB 조회 결과로 BoardModel 객체를 만들어 리스트에 추가합니다. 
				BoardModel board = new BoardModel(bno_db, writer_db, title_db, content_db, writeDate_db, fileName_db, savedFileName_db);
				boardList.add(board);
			}
			
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} finally {
			try {
				if(rs !=null) rs.close();
				if(stmt !=null) stmt.close();
				if(con !=null) con.close();
				
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		return boardList;
	}
} 
```

<br>
<br>

## **취약점 분석**
---

```java
private static final String PASSWORD = "123456";
```

해당 부분에서 프로그램 코드 내부에 하드코딩된 중요정보를 포함하고 있다. 이를 이용하여 내부 인증에 사용하거나 외부 컴포넌트와 통신을 하는 경우, 관리자 정보가 노출될 수 있다.

<br>

이를 방지하기 위해선 비밀번호 등의 중요 정보는 암호화하여 별도의 파일에 저장하고, 암호화된 비밀번호를 복호화하여 사용해야 한다.

<br>
<br>

## **안전한 코드**
---
```java
package com.openeg.secolab.test.controller;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Repository;

/* application.properties 파일의 내용은 다음과 같습니다. 
 * 
 * driver = org.hsqldb.jdbc.JDBCDriver
 * url = jdbc:hsqldb:~/board
 * user = secolab
 * encryptedPw = KqT0CSWsRFI2bCHbwM9rVA==
 * 
 * */

@Repository
public class SecureBoardTestDAO {

	List<BoardModel> boardList;
	BoardModel board;

	public List<BoardModel> showBoardList() {

		Connection con = null;
		Statement stmt = null;
		ResultSet rs = null;
		boardList = null;
		int bno_db;
		String writer_db, title_db, content_db, fileName_db, savedFileName_db = null;
		Date tmp;

		Properties props = getProperties("application.properties");
		final String DRIVER = props.getProperty("driver");
		final String URL = props.getProperty("url");
		final String USER = props.getProperty("id");
		final String PASSWORD = pros.getProperty("encryptedPw");

		String password = decrypt(PASSWORD);
		Class.forName(DRIVER);

		try {

			if (isNotNull(URL, USER, PASSWORD)) {
				// AES 암호화 알고리즘을 사용해 Cipher 객체를 생성합니다.

				con = DriverManager.getConnection(URL, USER, password);
				stmt = con.createStatement();
				rs = stmt.executeQuery("select * from board order by id desc");

				boardList = new ArrayList<BoardModel>();
				while (rs.next()) {
					bno_db = rs.getInt("id");
					writer_db = rs.getString("writer");
					title_db = rs.getString("title");
					content_db = rs.getString("content");
					tmp = rs.getDate("writeDate");
					fileName_db = rs.getString("fileName");
					savedFileName_db = rs.getString("savedFileName");

					SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
					String writeDate_db = formatter.format(tmp);

					BoardModel board = new BoardModel(bno_db, writer_db, title_db, content_db, writeDate_db,
							fileName_db, savedFileName_db);

					boardList.add(board);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} finally {
			try {
				if (rs != null)
					rs.close();
				if (stmt != null)
					stmt.close();
				if (con != null)
					con.close();
			} catch (SQLException e) {
				e.printStackTrace();
			}
		}
		return boardList;
	}

	public Properties getProperties(String propFile) {
		Properties props = new Properties();
		InputStream is = getClass().getClassLoader().getResourceAsStream(propFile);

		try {
			if (is != null) {
				props.load(is);
				return props;
			} else {
				throw new FileNotFoundException("프로퍼티 파일을 찾을 수 없습니다.");
			}
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	public String decrypt(String codedPassword) {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec ivParamSpec = new IvParameterSpec(getKey().getEncoded(), 0, 128);

		/* 패스워드 복호화를 위한 Cipher의 작동 모드를 작성. */
		cipher.init(Cipher.DECRYPT_MODE, getKey(), ivParamSpec);
		/* 암호화된 패스워드를 복호화하는 메소드를 작성. */
		byte[] decryptedPw = cipher.doFinal(Base64.getDecoder().decode(codedPassword));
		return new String(decryptedPw);
	}

	publiSecretKeySpecec getKey() {
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

	// 외부 입력값의 Null 체크를 위한 메소드입니다.
	public boolean isNotNull(String URL, String USER, String PASSWORD) {
		if (URL != null && !"".equals(URL) 
				&& USER != null && !"".equals(USER) 
				&& PASSWORD != null && !"".equals(PASSWORD)) {
			return true;
		}
		return false;
	}
}
```
