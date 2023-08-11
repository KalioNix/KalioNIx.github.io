---
title: '[ Java ] SQL Injection'
date: '2023-08-11T09:00:00.000Z'
categories: ['Secure Coding', 'Java']
tag : ['Secure Coding', 'Java']
---
## **취약한 코드**

---

```java
package kr.co.openeg.lab.test.util;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

public class DBRead {
	public String readDB(String id, String passwd) {
		StringBuffer result=new StringBuffer();
		Connection con=null;
		Statement st=null;
		ResultSet rs=null;
		try {
			con = EConnection.getConnection(this);
			st = con.createStatement();
			rs = st.executeQuery("select * from board_member where userid='"+id+"' and userpw='"+passwd+"'");
   		    if ( rs.next() ) {
			       result.append("ID: "+rs.getString(2));
			       result.append("PASSWORD: "+rs.getString(3));
			}
		} catch (SQLException e1) {
			// TODO Auto-generated catch block
			result.append("요청처리에러발생");
		}

		if ( rs != null ) try { rs.close(); }catch(SQLException e){}
		if ( st != null ) try { st.close(); }catch(SQLException e){}
		if ( con != null ) try { con.close(); }catch(SQLException e){}
          
		return result.toString();
	}
}

class EConnection {
    public static Connection getConnection(Object o) {
   	 Connection con=null;
   	 Properties properties = new Properties();
   	 
   	 try {   		 
   	      properties.load( o.getClass().getClassLoader()
   	    		               .getResourceAsStream("config/dbconn.properties"));
   	 } catch (IOException e) {
   		System.out.println("DB 정보 로드 실패");
   	    return null;
   	 }
   	 String driver = properties.getProperty("jdbc.driver");
   	 String url = properties.getProperty("jdbc.url");
   	 String username = properties.getProperty("jdbc.username");
   	 String password = properties.getProperty("jdbc.password");
   
   	 try {
   	    Class.forName(driver); 
   	    con=DriverManager.getConnection(url,username,password);
   	 }catch(Exception e){
   		 System.out.println("DB 연결 오류");
   		 return null;
   	 } 
   	 return con;
    }
} 
```

<br>
<br>

## **취약점 분석**

---

``rs = st.executeQuery("select * from board_member where userid='"+id+"' and userpw='"+passwd+"'");``

사용자로부터 입력받은 id와 passwd 값을 직접 문자열에 연결하여 SQL 쿼리를 생성하고 실행하고 있다.

이런 방식은 사용자의 입력을 쿼리에 삽입하기 때문에, 공격자가 악의적인 입력을 제공하여 쿼리의 동작을 변경하거나 데이터를 노출시킬 수 있는 SQL Injection 공격에 취약하다.

<br>

이러한 취약점을 방지하려면 사용자의 입력 값을 직접 쿼리에 삽입하지 않고, PreparedStatement를 사용하여 쿼리를 구성하고 입력 값을 매개변수로 처리해야 한다.

이렇게 하면 입력 값이 쿼리의 일부로 해석되는 것이 아니라 값으로 취급되어 SQL 인젝션 공격을 예방할 수 있다.

<br>
<br>

## **안전한 코드**

---

```java
package kr.co.openeg.lab.test.util;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.util.Properties;

public class DBReadSec {
	public String readDB(String id, String passwd) {
		StringBuffer result=new StringBuffer();
		Connection con=null;
		//Statement st=null;
		PreparedStatement ps=null;
		ResultSet rs=null;
		try {
			con = EConnection2.getConnection(this);

			// st = con.createStatement();
			sql = "select * from board_member where userid=? and userpw=?";
   		  
			ps = con.prepareStatement(sql);
			ps.setString(1, id);
			ps.setString(2, passwd);

			rs = ps.executeQuery();

		} catch (SQLException e1) {
			result.append("요청처리에러발생");
		}

		if ( rs != null ) try { rs.close(); }catch(SQLException e){}
		if ( ps != null ) try { ps.close(); }catch(SQLException e){}
		if ( con != null ) try { con.close(); }catch(SQLException e){}
          
			return result.toString();
	}
}

class EConnection2 {
    public static Connection getConnection(Object o) {
   	 Connection con=null;
   	 Properties properties = new Properties();
   	 
   	 try {   		 
   	      properties.load( o.getClass().getClassLoader()
   	    		               .getResourceAsStream("config/dbconn.properties"));
   	 } catch (IOException e) {
   		System.out.println("DB 정보 로드 실패");
   	    return null;
   	 }
   	 String driver = properties.getProperty("jdbc.driver");
   	 String url = properties.getProperty("jdbc.url");
   	 String username = properties.getProperty("jdbc.username");
   	 String password = properties.getProperty("jdbc.password");
   
   	 try {
   	    Class.forName(driver); 
   	    con=DriverManager.getConnection(url,username,password);
   	 }catch(Exception e){
   		 System.out.println("DB 연결 오류");
   		 return null;
   	 } 
   	 return con;
    }
}
```
