---
title: "[ Java ] File Upload Vulnerability"
date: "2023-08-18 01:00:00"
categories: ['Secure Coding', 'Java']
tag: ['secure Coding', 'java']
---

## **취약한 코드**
---
```java
package kr.co.openeg.lab.test.controller;

import java.io.File;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.servlet.ModelAndView;

import kr.co.openeg.lab.test.model.BoardModel;
import kr.co.openeg.lab.test.service.BoardService;
import kr.co.openeg.lab.test.util.ConvertInput;

public class BoardController {

	@Autowired
	private BoardService service;

	@RequestMapping(value="write", method=RequestMethod.GET)
	public ModelAndView boardWrite(ModelAndView mav, HttpSession session) {

		mav.setViewName("board/write");
		return mav;
	}

	@RequestMapping(value="write", method=RequestMethod.POST)
	public ModelAndView boardWriteProc(ModelAndView mav, @ModelAttribute("BoardModel") BoardModel boardModel,
			MultipartHttpServletRequest request, HttpSession session) throws ServletException {

		try {

			MultipartFile file = request.getFile("file");

			if (file != null && !"".equals(file.getOriginalFilename())) {

				String fileName = file.getOriginalFilename();

				if (fileName != null) {

					String uploadPath = System.getProperty("user.dir") + "/files/";
					File uploadFile = new File(uploadPath + fileName);

					try {
						file.transferTo(uploadFile);
					} catch (Exception e) {
						mav.addObject("msg", false);
						mav.addObject("fuploaderror", false);
						throw new ServletException("파일 업로드 에러");
					}
				} else {
					mav.addObject("msg", false);
					mav.addObject("uploaderror", false);
					throw new ServletException("파일 확장자 에러");
				}
				boardModel.setFileName(fileName);
			}

			String title = request.getParameter("title");
			boardModel.setTitle(title);

			String content = boardModel.getContent().replaceAll("\r\n", "<br />");
			String convertedContent = ConvertInput.ConvertInputValue(content);
			boardModel.setContent(convertedContent);

			String writerId = request.getParameter("writerId");
			boardModel.setWriter(writerId);

			if (service.writeArticle(boardModel)) {
				mav.setViewName("redirect:/");
				return mav;
			}
		} catch (ServletException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		mav.setViewName("board/write");
		return mav;
	}
} 
```

<br>
<br>

## **취약점 분석**
---

사용자가 업로드한 파일을 아무런 검사 없이 서버에 저장하고 있다.

이런 경우 공격자는 악의적인 파일을 업로드하고 실행시킬 수 있다. 

<br>

업로드 시 입력된 파일이 허용되는 형식인지 확인하여 해당 취약점을 방지할 수 있다.

또한 파일의 사이즈를 제한하고, 파일명을 추측할 수 없게 하는 방법이 있다.

<br>
<br>

## **안전한 코드**
---

```java
package kr.co.openeg.lab.test.controller;

import java.io.File;
import java.util.Date;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.servlet.ModelAndView;

import kr.co.openeg.lab.test.model.BoardModel;
import kr.co.openeg.lab.test.service.BoardService;
import kr.co.openeg.lab.test.util.ConvertInput;

public class SecureBoardController {

	@Autowired
	private BoardService service;
	private int MAX_FILE_SIZE = 1024 * 1024 * 5;

	@RequestMapping(value = "write", method = RequestMethod.GET)
	public ModelAndView boardWrite(ModelAndView mav, HttpSession session) {

		mav.setViewName("board/write");
		return mav;
	}

	@RequestMapping(value = "write", method = RequestMethod.POST)
	public ModelAndView boardWriteProc(ModelAndView mav, @ModelAttribute("BoardModel") BoardModel boardModel,
			MultipartHttpServletRequest request, HttpSession session) throws ServletException {

		try {

			MultipartFile file = request.getFile("file");

			if (file != null && !"".equals(file.getOriginalFilename())) {

				/* 파일사이즈 제한을 위해 첨부된 파일의 사이즈를 가져오는 메소드와 파일 최대사이즈 변수를 사용*/
				int fileSize = (int) file.getSize();
				if (fileSize > MAX_FILE_SIZE) {
					mav.addObject("msg", false);
					mav.addObject("fsizeerror", false);
					throw new ServletException("파일 용량 제한 에러");
				}

				String fileName = file.getOriginalFilename();
				String savedFileName = null;

				if (fileName != null) {
					/* pdf파일만 업로드 가능하도록 제약 설정 */
					if (fileName.toLowerCase().endsWith(".pdf")) {

						String uploadPath = System.getProperty("user.dir") + "/files/";

						/** 저장하는 파일명은 랜덤하게 생성해서 사용하도록 코드 작성 */
						savedFileName = UUID.randomUUID().toString();
						File uploadFile = new File(uploadPath + savedFileName);

						try {
							file.transferTo(uploadFile);
						} catch (Exception e) {
							mav.addObject("msg", false);
							mav.addObject("fuploaderror", false);
							throw new ServletException("파일 업로드 에러");
						}
					} else {
						mav.addObject("msg", false);
						mav.addObject("uploaderror", false);
						throw new ServletException("파일 확장자 에러");
					}
				}
				boardModel.setFileName(fileName);
				boardModel.setSavedFileName(savedFileName);
			}

			String title = request.getParameter("title");
			boardModel.setTitle(title);

			String content = boardModel.getContent().replaceAll("\r\n", "<br />");
			String convertedContent = ConvertInput.ConvertInputValue(content);
			boardModel.setContent(convertedContent);

			String writerId = request.getParameter("writerId");
			boardModel.setWriter(writerId);

			if (service.writeArticle(boardModel)) {
				mav.setViewName("redirect:/");
				return mav;
			}
		} catch (ServletException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

		mav.setViewName("board/write");
		return mav;
	}
}
```