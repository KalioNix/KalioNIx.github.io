---
title: "[ Java ] 부적절한 인가"
date: "2023-08-25 03:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure coding', 'java']
---

## **취약한 코드**
---

```java
package com.openeg.secolab.test.controller;

import java.io.File;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

public class BoardTestController {
	@Autowired
	private BoardService service;

	@PostMapping(value = "/board/delete")
	public ModelAndView userDeleteProc(ModelAndView mav, HttpServletRequest request, HttpSession session) {
		String action = request.getParameter("action");

		if (action != null && action.equals("delete")) {

			int idx = Integer.parseInt(request.getParameter("idx"));
			BoardModel board = service.getOneArticle(idx);

			List<BoardCommentModel> commentList = service.getCommentList(idx);
			if (commentList.size() > 0) {
				mav.addObject("errMsg", "댓글이 존재하여 삭제할 수 없습니다.");
				mav.addObject("idx", idx);
				mav.setViewName("redirect:view");
			} else {
				// 첨부파일의 존재 여부를 확인하여 파일까지 삭제합니다. 
				if (board.getFileName() != null) {
					String uploadPath = request.getContextPath() + "/uploadFiles/";
					File removeFile = new File(uploadPath + board.getFileName());
					removeFile.delete();
				}
				service.deleteArticle(idx);
				// 게시글 목록 페이지를 반환합니다. 
				mav.setViewName("redirect:list");
			}
		}
		return mav;
	}
}

class BoardService {

	@Autowired 
	BoardDao dao;

	public BoardModel getOneArticle(int idx) {
		// DB에서 글 번호가 idx인 글을 조회하는 메소드입니다.
		return dao.selectArticle(idx);
	}

	public List<BoardCommentModel> getCommentList(int idx) {
		//  DB에서 글 번호가 idx인 글에 등록된 댓글을 조회하는 메소드입니다.
		return dao.selectCommentList(idx);
	}

	public void deleteArticle(int idx) {
		// 코드 생략 - DB에서 글 번호가 idx인 글을 삭제하는 메소드입니다.
		dao.deleteArticle(idx);
	}
}

class BoardModel {
	private int bno_db;
	private String writer_db, title_db, content_db, writeDate_db, fileName_db, savedFileName_db, fileName;

	public BoardModel(int bno_db, String writer_db, String title_db, String content_db, 
			String writeDate_db, String fileName_db, String savedFileName_db) {
	}
	
	// 코드 생략 - getter, setter 메소드가 생략되었습니다. 
	public String getFileName() { return fileName; }
	public void setFileName(String fileName) { this.fileName = fileName; }
}

class BoardCommentModel {
	private int cno;
	private String commentWriter, commentContent, commetWriteDate;
} 
```

<br>
<br>

## **취약점 분석**
---

```java
service.deleteArticle(idx);
```

해당 부분에서 요청을 하는 사용자의 delete 작업 권한 확인 없이 글 삭제를 수행하고 있다. 프로그램이 모든 실행가능한 경로에 대해서 접근제어를 검사하지 않거나 불완전하게 검사하는 경우, 공격자는 접근 가능한 실행경로를 통해 정보를 유출 또는 조작 할 수 있는 보안 취약점이 존재한다.

<br>

사용자 정보에서 해당 사용자가 작업의 권한이 있는지 확인한 뒤 작업을 수행하여 취약점을 방지할 수 있다.

<br>
<br>

## **안전한 코드**
---

```java
package kr.co.openeg.lab.test.controller;

import java.io.File;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties.User;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;

import kr.co.openeg.lab.test.model.BoardModel;
import kr.co.openeg.lab.test.service.BoardService;

public class SecureBoardTestController {

	@Autowired
	private BoardService service;

	@PostMapping(value = "/board/delete")
	public ModelAndView userDeleteProc(ModelAndView mav, HttpServletRequest request, HttpServletResponse response,
			HttpSession session) {
		String action = request.getParameter("action");
		String userId = (String) session.getAttribute("userId");
		// 요청으로부터 작성자 아이디를 가져옵니다. 
		String writerId = request.getParameter("writerId");

		/* 사용자 id와 작성자 id가 일치하는지 여부를 확인할 수 있는 메소드*/
		if (action != null && action.equals("delete") && userId.equals(writerId)) {
			int idx = Integer.parseInt(request.getParameter("idx"));
			BoardModel board = service.getOneArticle(idx);

			List<BoardCommentModel> commentList = service.getCommentList(idx);
			if (commentList.size() > 0) {
				mav.addObject("errMsg", "댓글이 존재하여 삭제할 수 없습니다.");
				mav.addObject("idx", idx);
				mav.setViewName("redirect:view");
			} else {
				// 첨부파일의 존재 여부를 확인하여 파일까지 삭제합니다. 
				if (board.getFileName() != null) {
					String uploadPath = request.getContextPath() + "/uploadFiles/";
					File removeFile = new File(uploadPath + board.getFileName());
					removeFile.delete();
				}
				service.deleteArticle(idx);
				// 게시글 목록 페이지를 반환합니다. 
				mav.setViewName("redirect:list");
			}
		} else {
			mav.addObject("errMsg", "삭제 권한이 없습니다.");
			mav.addObject("idx", idx);
			mav.setViewName("redirect:view");
		}
		return mav;
	}
}

class BoardService {

	@Autowired 
	BoardDao dao;

	public BoardModel getOneArticle(int idx) {
		// DB에서 글 번호가 idx인 글을 조회하는 메소드입니다.
		return dao.selectArticle(idx);
	}

	public List<BoardCommentModel> getCommentList(int idx) {
		//  DB에서 글 번호가 idx인 글에 등록된 댓글을 조회하는 메소드입니다.
		return dao.selectCommentList(idx);
	}

	public void deleteArticle(int idx) {
		// DB에서 글 번호가 idx인 글을 삭제하는 메소드입니다.
		dao.deleteArticle(idx);
	}
}

class BoardModel {
	private int bno_db;
	private String writer_db, title_db, content_db, writeDate_db, fileName_db, savedFileName_db, fileName;

	public BoardModel(int bno_db, String writer_db, String title_db, String content_db, 
			String writeDate_db, String fileName_db, String savedFileName_db) {
	}
	
	// 코드 생략 - getter, setter 메소드가 생략되었습니다. 
	public String getFileName() { return fileName; }
	public void setFileName(String fileName) { this.fileName = fileName; }
}

class BoardCommentModel {
	private int cno;
	private String commentWriter, commentContent, commetWriteDate;
}
```