---
title: Digital Dragon CTF 2024 Writeup
description: "CTF Digital Dragons: The Cybersecurity Challenge 2024 là cuộc thi do Trường Đại học Công nghệ Thông tin & Truyền thông Việt - Hàn (VKU) tổ chức"
cover: https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/thumb.png
categories:
  - [CTF, Writeups]
tags:
  - web
  - forensics
  - reverse
  - pwn
  - osint
  - phishing
  - boot2root
  - network
indexing: true
---

Hi, tụi mình là team **3r0th3r CC**. Đợt vừa rồi team mình đã đứng **hạng 17** vòng **Tứ Kết** của cuộc thi **Digital Dragon CTF** và cũng clear được hết tất cả challenge

![17th](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/17th.png)

Đây sẽ là bài writeup của vòng đó đồng thời cũng là bài debut của bọn mình <3

# Web

## Treasure of Hanoi

Url: https://digitaldragonsctf-treasure-of-hanoi.chals.io

![treasure-of-hanoi](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Web/host-ping-checker.png)

Nhìn sơ qua, ta có thể thấy được đây chính là trang cho phép ping tới các host. Như mọi khi thì mình bật Burp Suite lên, intercept request rồi test thôi :3

Sau khi ngồi mò tí thì mình nhận ra có vài ký tự đặc biệt không bị lọc như:

```
$\;.
```

Với kinh nghiệm có được từ các giải CTF trước, không quá khó để đoán ra đây là vuln **Command Injection**

```shell
;ls
```

![detect](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Web/detect.png)

Nhiệm vụ của ta đơn giản chỉ là tìm xem file chứa flag nằm ở đâu rồi đọc nó thôi

Tuy nhiên, vấn đề lúc này lại phát sinh, dấu cách bị lọc nên ta không thể thêm option `-al` vào lệnh `ls` được. Để giải quyết thì mình đã thêm `$IFS` thay cho dấu cách để bypass

```shell
;ls$IFS-al
```

![flag](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Web/flag.txt.png)

Bây giờ, mình đã biết flag nằm trong file `.flag.txt`. Nhưng tới lúc đọc flag thì mình nhận ra lệnh `cat` cũng bị lọc mất =))

Sau một hồi nghiên cứu, nói thẳng ra là search Google, mình đã tìm ra cách. Cụ thể là ta chỉ cần thêm `\` vào kế mỗi ký tự của lệnh là sẽ bypass được

Payload cuối cùng:

```shell
;c\a\t$IFS.flag.txt
```

> **FLAG: flag{50c49f64befc0f84c827c7771c9ebdd5}**

Link: https://viblo.asia/p/bypass-os-command-injection-XL6lA4rNZek

## The Lost Diamond of Hanoi

Url: https://digitaldragonsctf-the-lost-diamond-of-hanoi.chals.io/

![the-lost-diamond-of-hanoi](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Web/the-lost-diamond-of-hanoi.png)

Đề này đại loại bảo rằng mình phải tìm cái kho báu được giấu trong lòng ngôi đền bí ẩn gì đó khá rườm rà nên mình xem source luôn cho lẹ

```js
// File /static/script.js
const searchInput = document.getElementById("searchInput");
const searchResults = document.getElementById("searchResults");
const description = document.getElementById("description");

searchInput.addEventListener("input", async () => {
  const searchTerm = searchInput.value.trim();
  if (searchTerm === "") {
    clearSearchResults();
    return;
  }

  const response = await fetch(
    `/search?term=${encodeURIComponent(searchTerm)}`
  );
  const data = await response.json();

  clearSearchResults();
  data.forEach((result) => {
    const resultElement = document.createElement("div");
    resultElement.textContent = result.hint_name;
    resultElement.classList.add("hint-method");
    resultElement.addEventListener("click", async () => {
      const descriptionResponse = await fetch(
        `/description?hint=${encodeURIComponent(result.hint_name)}`
      );
      const descriptionData = await descriptionResponse.json();
      searchInput.value = "";
      clearSearchResults();
      description.innerHTML = `<strong>${result.hint_name}</strong>: ${descriptionData.description}`;
    });
    searchResults.appendChild(resultElement);
  });
});

function clearSearchResults() {
  searchResults.innerHTML = "";
  description.innerHTML = "";
}

function openTab(tabName) {
  var tabContents = document.getElementsByClassName("tab-content");
  for (var i = 0; i < tabContents.length; i++) {
    tabContents[i].classList.remove("active");
  }
  var tabs = document.getElementsByClassName("tab");
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].classList.remove("active");
  }
  document.getElementById(tabName).classList.add("active");
  event.target.classList.add("active");
}

/* Remove /api/debug in production */
```

Hồi đầu mình không để ý lắm nên cứ ngồi test ở endpoint `/search` xem có bị dính lỗi **SQL Injection** không, mãi sau nhìn xuống dưới mới biết là có `/api/debug` nằm ở dòng cuối .\_.

Lúc này mình thử gửi request `GET` để check và server trả về `405 METHOD NOT ALLOWED`. Vì vậy mình đã chuyển sang `POST` request xong lại nhận được `400 BAD REQUEST` :)

Đọc lại file `script.js`, có thể thấy server sử dụng **json**, vì vậy nên ta cần phải đổi thành `Content-Type: application/json` mới được

![admin](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Web/admin.png)

Nhiệm vụ lúc này là làm sao để lên được `admin`, tuy nhiên thì mọi chuyện không hề đơn giản

![error](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Web/error.png)

Sau khi ~~nghiên cứu,~~ search Google, mình thấy dạng này khá giống vuln **NoSQL Injection** nên đã test vài payload nhưng không thành công

Vào lúc gần như bất lực nhất thì mình lại chợt nhớ lại [1 challenge mà mình đã viết writeup trước đây](https://t3l3sc0p3.github.io/posts/knightctf-2024-writeup/#gain-access-2-440-pts)

Nguyên lý là ta sẽ biến nó thành 1 mảng, trong đó sẽ có chứa cả value mà mình mong muốn và value hợp lệ, từ đó qua mặt hệ thống, và cách này thành công thật

![flag](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Web/flag-json.png)

![noice](https://i.imgur.com/jwYlN9G.gif)

> **FLAG: flag{a42c3633fa1422d6356ecafc6849788e}**

Link:

- https://t3l3sc0p3.github.io/posts/knightctf-2024-writeup/#gain-access-2-440-pts
- https://www.w3schools.com/js/js_json_arrays.asp

# Forensics

## Simple File

Sau khi tui phân tích thì, cuối cùng nhất là sử dụng `xxd` để xem bên trong chứa cái gì nhé

Sử dụng `xxd` để xem

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/for1.png)

Dựa vào thông tin có được thì tìm kiếm Google `Flatedecode pdf`, dưới đây là đoạn code được sử dụng

```python
#Credit: https://gist.github.com/averagesecurityguy/ba8d9ed3c59c1deffbd1390dafa5a3c2
import re
import zlib

pdf = open("some_doc.pdf", "rb").read()
stream = re.compile(rb'.*?FlateDecode.*?stream(.*?)endstream', re.S)

for s in stream.findall(pdf):
    s = s.strip(b'\r\n')
    try:
        print(zlib.decompress(s))
        print("")
    except:
        pass
```

Chạy file python thì xuất ra rất nhiều dòng lạ hoắc nhỉ :))

Thật ra nó là các đoạn hex thôi, lướt đọc thì sẽ 1 đoạn rất lạ, hãy thử decode nó xem

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/for2.png)

Trong đây tui sử dụng [Cyber Chef](https://gchq.github.io/CyberChef/)

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/for3.png)

## Lạc Long Quân’s Mystery

Sử dụng `Volatility3`

```shell
python ../../../Tools/Tools\ DF/volatility3/vol.py -f ddc_mystery\(1\).raw windows.pslist.PsList
```

Thấy `MRCv120.exe` chứ? Hãy thử dump ra xem nó là gì đi chứ tui tò mò lắm rồi

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/mem1.png)

```shell
python ../../../Tools/Tools\ DF/volatility3/vol.py -f ddc_mystery\(1\).raw windows.filescan.FileScan | grep -i mrcv120
0x6737910  100.0\Users\ddcmystery\Downloads\MRCv120.exe	216
0x3b14c270	\Users\ddcmystery\Downloads\MRCv120.exe	216
0x3b14cf20	\Users\ddcmystery\Downloads\MRCv120.exe	216
```

Để ý, ta sẽ dump bằng `--physaddr`

> `addr` của `MRCv120.exe` là `0x6737910`

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/mem2.png)

```shell
python ../../../Tools/Tools\ DF/volatility3/vol.py -f ddc_mystery\(1\).raw -o rar/ windows.dumpfiles.DumpFiles --physaddr 0x6737910
```

Với `-o` là đầu ra của các file đó

Tiến hành đổi tên `file...MRCv120.exe.dat` thành `MRVc120.exe`

```shell
cp file.0xfa80036e8270.0xfa80036520c0.DataSectionObject.MRCv120.exe.dat MRCv120.exe && rm -f file.*
```

Sử dụng `md5` của file để tìm trên [VirusTotal](https://www.virustotal.com/gui/home/upload)

```shell
md5sum MRCv120.exe
ec0c00b0a133a2ac4be9eca39fba8cee  MRCv120.exe
```

Dù nó là `Trojan` những sau 1 lúc lục lọi thì vẫn không thấy gì nên .-.

Ta sử dụng `filescan` như sau để tiếp tục phân tích

```shell
python ../../../Tools/Tools\ DF/volatility3/vol.py -f ddc_mystery\(1\).raw windows.filescan.FileScan | grep -i ddcmystery
```

> `ddcmystery` là username

`StickyNotes.snt` là nơi mà ứng dụng `Sticky Notes` lưu trữ các ghi chú mà người dùng tạo ra

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/mem3.png)

> Tiến hành `dump` như cũ

```shell
python ../../../Tools/Tools\ DF/volatility3/vol.py -f ddc_mystery\(1\).raw -o rar windows.dumpfiles --physaddr 0x3d7f2a10

cp file.0x3d7f2a10.0xfa80035f28b0.DataSectionObject.StickyNotes.snt.dat Stickynots.snt && rm -f file.*
```

Tui đã tìm đc thứ thú vị ở đây rồi

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/mem4.png)

Sử dụng `Tor Browser`

```
http://2xyr7jug4b5uhndzelsf7vgrxygttutc6h5mqzpwp7y6blk6owhxliqd.onion/preventpath/
```

Thấy có file tải về được, cũng tò mò :))

> `.enc` là bị mã hóa rồi nha, phải có passwd mới được

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/mem5.png)

Vào `view-source` xem có gì khai thác được không, yeh ban đầu tôi nhìn sơ qua đã bỏ lỡ

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/mem6.png)

```
http://2xyr7jug4b5uhndzelsf7vgrxygttutc6h5mqzpwp7y6blk6owhxliqd.onion/preventpath/data/flag.txt
```

Done :b

# Boot2Root & Net

2 challs này cơ bản là giống nhau vì đề có lỗ hổng... (chắc vậy idk :v)

Việc của ta là `Extract` file `.ova`

> Vì file `.ova` là dạng nén bao gồm file mô tả `OVF`, file đĩa thường có định dạng `.vmdk`, file `.mf` để đảm bảo tính toàn vẹn
> Trong đó `.vmdk` là 1 tệp chứa các đĩa (tui đã sử dụng chỗ này để grep flag :b -> do không bị mã hóa nên khá ez)

Sau khi `Extract` vào trong tệp đó sẽ thấy các tệp đã nói trên, tiếp theo đổi đuôi `.vmdk` -> `.zip` và `Extract` tiếp thôi

## BTR-3

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/btr1.png)

## Shipped & docked

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/net1.png)

# Phissing

Đưa `url` lên [VirusTotal](https://www.virustotal.com/gui/home/upload) để check

![image](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Forensic/phissing1.png)

Sau đó ta sẽ tìm thấy địa chỉ IP khá đáng ngờ, truy cập vào ta sẽ thấy thêm 1 file `onedrive.zip`

Tải file đó xuống và giải nén ra, flag sẽ nằm ở file `mail.php` :b

```php
<?php


$email = array("phish@digidragonsctf.com");  //PUT YOUR EMAIL HERE!!!
$telegramTOKEN = "12345678:5ab7fbc37fe19710e6e764bdfb931969"; //PUT YOUR TELEGRAM TOKEN HERE!!! PS : Hex value is your flag
$telegramID = "12345678";   //PUT YOUR ID HERE!!!


?>
```

# OSINT

Đầu tiên, challenge cho ta 1 cái username `ddcScapeG0at24`. Sử dụng tool [instantusername](https://instantusername.com) hoặc 1 số tool như `sherlock`, ta sẽ tìm được tài khoản [GitHub](https://github.com/ddcScapeG0at24/)

Sau đó từ tài khoản [GitHub](https://github.com/ddcScapeG0at24/), ta tìm được tài khoản [Twitter (X)](https://x.com/ddcScapeG0at24) rồi [LinkedIn](https://www.linkedin.com/in/ddcScapeG0at24/)

Mọi thứ đều hướng tới tài khoản [LinkedIn](https://www.linkedin.com/in/ddcScapeG0at24/), tuy nhiên tới đây lại là hẻm cụt. Team mình đã dành ra gần 3 tiếng vô nghĩa chỉ để ngồi mò xem có thể moi được gì từ cái acc này hay không .\_\_.

Xong bọn mình lại mò về [GitHub](https://github.com/ddcScapeG0at24/). Lúc này vài member trong team phát hiện ra email trong repo tại [commit này](https://github.com/ddcScapeG0at24/Phishing1/commit/915f4c5a37e714d88f23f0a89d5e7432080a2629)

```
ddcScapeG0at24@gmail.com
```

Nên tụi mình đã sử dụng tool [Epieos](https://epieos.com/) để trích xuất thông tin. Sau một lúc ngồi mò thì tụi mình tìm được [Calendar](https://calendar.google.com/calendar/u/0/embed?src=ddcScapeG0at24@gmail.com)

Khi bấm sang `September 2024` để xem, tụi mình thấy 1 trang web và thông tin để đăng nhập

```
Server: https://digitaldragonsctf-ddc24scapeg0at.chals.io/
User: ddc24
Password: ddcScapeG0at24
```

Giờ thì chỉ cần đăng nhập vào lấy flag nữa thôi là xong

![flag](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/OSINT/flag.png)

> **FLAG: flag{a432a9312d26242a97984f23308e49b6}**

# Reverse Engineering

## Happiness

Đầu tiên thì mình luôn kiểm tra xem file nó là gì

```shell
$ file "./happiness-dist"
happiness-dist: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2a6fe990565d61a0ed6aa417f41ac043a300556b, for GNU/Linux 4.4.0, with debug_info, not stripped
```

Nó là một file `ELF 64-bit`

Sau khi chạy file thì ta thấy nó hiện ra một giao diện GUI đăng nhập để nhập `Username` và `Password`

![happiness_img](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Rev/e935aa1d809830f6a1143dc66cb7b9d9.png)

Sau khi quăng vô [IDA](https://hex-rays.com/ida-pro/) và lướt sơ qua hàm `main` thì có thể thấy một hàm có tên là `on_button_clicked`.

```cpp
g_signal_connect_data(button, "clicked", on_button_clicked, grid, 0LL, 0LL);
```

Cụ thể, `g_signal_connect_data` là một hàm được sử dụng để kết nối một tín hiệu (signal) với một callback function (hàm sẽ được gọi khi tín hiệu đó được phát ra). Trong trường hợp này:

`button`: Là đối tượng mà bạn đang kết nối tín hiệu. Trong trường hợp này, đó là một nút (`button`).
`"clicked"`: Là tên của tín hiệu. Tín hiệu `"clicked"` sẽ được phát ra khi người dùng nhấp vào nút.
`on_button_clicked`: Là tên của hàm callback sẽ được gọi khi tín hiệu `"clicked"` được phát ra. Đây là hàm mà bạn cần viết để định nghĩa hành vi khi nút bị nhấp.
`grid`: Đây là dữ liệu bạn muốn truyền vào hàm callback `on_button_clicked`. Nó có thể là bất kỳ dữ liệu nào mà bạn cần trong hàm callback.
`0LL, 0LL`: Đây là các flags và dữ liệu người dùng khác, thường được đặt mặc định thành `0LL` nếu không cần thiết sử dụng.
Dòng mã này sẽ khiến hàm `on_button_clicked` được gọi khi nút button được nhấp, và `grid` sẽ được truyền vào hàm đó.

> **Tóm cái váy lại, dòng trên là xử lý sự kiện khi nhấp vào nút `Login`**

Xem mã giả của hàm `on_button_clicked` có thể thấy được nó lấy dữ liệu đầu vào của `Username` và `Password` thông qua `username_entry` và `password_entry` và được lưu vào biến `username` và `password`

```cpp
-------------------------------------------------------------------------------------------
v5 = g_object_get_data(v4, "username_entry");                          <-- username_entry
username_entry = (GtkWidget *)g_type_check_instance_cast(v5, v3);
-------------------------------------------------------------------------------------------
v6 = gtk_widget_get_type();
v7 = g_type_check_instance_cast(grid, 80LL);
-------------------------------------------------------------------------------------------
v8 = g_object_get_data(v7, "password_entry");                          <-- password_entry
password_entry = (GtkWidget *)g_type_check_instance_cast(v8, v6);
-------------------------------------------------------------------------------------------
v9 = gtk_widget_get_type();
v10 = g_type_check_instance_cast(grid, 80LL);
v11 = g_object_get_data(v10, "result_label");
result_label = (GtkWidget *)g_type_check_instance_cast(v11, v9);
v12 = gtk_entry_get_type();
v13 = g_type_check_instance_cast(username_entry, v12);
username = (const char *)gtk_entry_get_text(v13);                       <-- username
v14 = gtk_entry_get_type();
v15 = g_type_check_instance_cast(password_entry, v14);
password = (const char *)gtk_entry_get_text(v15);                       <-- password
```

Tiếp tục lướt xuống dưới có thể thấy được nó đang kiểm tra xem `username` có phải là **"admin"** hay không. Nếu đúng thì nó sẽ sao chép chuỗi **admin** vào biến `admin_xored` và thực hiện một đoạn giải mã `encrypted_flag` (cờ bị mã hoá). Đoạn code mã hoá nhìn sơ qua thì cũng không có gì khó, chỉ đơn giản là sử dụng phép xor để xor chuỗi **admin** với **0xDE** sau đó lấy `encrypted_flag` xor với `admin_xored` ta sẽ được `decrypted_flag` và đây cũng chính là flag mà ta cần tìm.

```cpp
if ( !strcmp(username, "admin") )                                                  <---------- username == "admin"
  {
    strcpy(admin_xored, "admin");
    for ( i = 0; i < strlen(admin_xored); ++i )
      admin_xored[i] ^= 0xDEu;                                                     <---------- "admin" ^ 0xDE
    *(_QWORD *)encrypted_flag = 0xD58C87CBD0D2D6D9LL;
    *(_QWORD *)&encrypted_flag[8] = 0xDAD1868BDB8E838FLL;
    *(_QWORD *)&encrypted_flag[16] = 0x848BD987D38ED58DLL;
    *(_QWORD *)&encrypted_flag[24] = 0xD9DA86D48A88D9D2LL;
    *(_QWORD *)&encrypted_flag[30] = 0xCEDC8D89D2D0D9DALL;
-------------------------------------------------------------------------------
    for ( i_0 = 0; (unsigned int)i_0 <= 0x25; ++i_0 )
    {
      v16 = encrypted_flag[i_0];                                                    <---------- admin_xored ^ encrypted_flag
      decrypted_flag[i_0] = admin_xored[i_0 % strlen(admin_xored)] ^ v16;
    }
-------------------------------------------------------------------------------
    if ( !strcmp(password, decrypted_flag) )
    {
      result_text = (gchar *)g_strdup_printf("Access granted! Flag: %s", decrypted_flag);
      v17 = gtk_label_get_type();
      v18 = g_type_check_instance_cast(result_label, v17);
      gtk_label_set_text(v18, result_text);
      g_free(result_text);
      v32 = 0LL;
      v33 = 0x3FF0000000000000LL;
    }
```

Đến bước này có rất nhiều cách để tìm flag và cách nhanh nhất của mình là quăng vô gdb đặt breakpoint tại `if ( !strcmp(password, decrypted_flag) )` sau đó chạy chương trình bằng lệnh `run` hoặc `r`. Nhập `username` là **admin** và `password` có thể để trống rồi ấn `login`.

```shell
$ gdb "happiness-dist" --q
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.12
Reading symbols from happiness-dist...
gef➤  b* 0x0000555555556a8e
Breakpoint 1 at 0x555555556a8e: file happiness.c, line 86.
gef➤  r
Starting program: /home/kali/CTF/DDC/Rev/Happiness/happiness-dist
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff5c006c0 (LWP 11118)]
[New Thread 0x7ffff52006c0 (LWP 11119)]
[New Thread 0x7fffefe006c0 (LWP 11120)]

(happiness-dist:11109): Gtk-WARNING **: 02:15:10.070: Theme parsing error: gtk.css:2057:20: '' is not a valid color name

(happiness-dist:11109): Gtk-WARNING **: 02:15:10.070: Theme parsing error: gtk.css:2058:16: '' is not a valid color name

(happiness-dist:11109): Gtk-WARNING **: 02:15:10.071: Theme parsing error: gtk.css:2534:38: value 34 out of range. Must be from 0.0 to 1.0

(happiness-dist:11109): Gtk-WARNING **: 02:15:10.074: Theme parsing error: gtk.css:4993:38: value 34 out of range. Must be from 0.0 to 1.0

(happiness-dist:11109): Gtk-WARNING **: 02:15:10.077: Theme parsing error: gtk.css:7646:38: value 34 out of range. Must be from 0.0 to 1.0

(happiness-dist:11109): Gtk-WARNING **: 02:15:10.078: Theme parsing error: gtk.css:7785:51: value 34 out of range. Must be from 0.0 to 1.0
[New Thread 0x7fffef4006c0 (LWP 11121)]
[New Thread 0x7fffeea006c0 (LWP 11130)]

Thread 1 "happiness-dist" hit Breakpoint 1, 0x0000555555556a8e in on_button_clicked (widget=0x5555556a7ee0, data=0x55555561f680) at happiness.c:86
86      happiness.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007ffff7a2c531  →  0x696c2d6469726700
$rbx   : 0x25
$rcx   : 0x2
$rdx   : 0x00007fffffffadd0  →  "flag{86f831a81ae7f9c8c83bf29c6ecce92f}"
$rsp   : 0x00007fffffffad20  →  0x000055555561f680  →  0x00005555557080b0  →  0x00005555557adb00  →  0x0000000000000002
$rbp   : 0x00007fffffffae10  →  0x000055555571c120  →  0x0000000040000002
$rsi   : 0x00007fffffffadd0  →  "flag{86f831a81ae7f9c8c83bf29c6ecce92f}"
$rdi   : 0x00007ffff7a2c531  →  0x696c2d6469726700
$rip   : 0x0000555555556a8e  →  <on_button_clicked+674> call 0x5555555561c0 <strcmp@plt>
$r8    : 0x0
$r9    : 0xb
$r10   : 0x00007ffff6ce0dc0  →  0x0010001a0000723b (";r"?)
$r11   : 0x00007ffff6d78f10  →  <__strlen_sse2+0> pxor xmm0, xmm0
$r12   : 0xce
$r13   : 0x0
$r14   : 0x0
$r15   : 0x00007ffff6fadb60  →  <g_cclosure_marshal_VOID__VOIDv+0> endbr64
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffad20│+0x0000: 0x000055555561f680  →  0x00005555557080b0  →  0x00005555557adb00  →  0x0000000000000002      ← $rsp
0x00007fffffffad28│+0x0008: 0x00005555556a7ee0  →  0x00005555556efa70  →  0x000055555569c510  →  0x0000000000000003
0x00007fffffffad30│+0x0010: 0x0000002600000005
0x00007fffffffad38│+0x0018: 0x000055555561f680  →  0x00005555557080b0  →  0x00005555557adb00  →  0x0000000000000002
0x00007fffffffad40│+0x0020: 0x00005555556d0600  →  0x000055555563afb0  →  0x00005555556b1f90  →  0x0000000000000004
0x00007fffffffad48│+0x0028: 0x00005555557175d0  →  0x000055555563afb0  →  0x00005555556b1f90  →  0x0000000000000004
0x00007fffffffad50│+0x0030: 0x00005555556275d0  →  0x0000555555648b50  →  0x0000555555642ff0  →  0x0000000000000008
0x00007fffffffad58│+0x0038: 0x0000555555712690  →  0x0000006e696d6461 ("admin"?)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555556a81 <on_button_clicked+661> mov    rax, QWORD PTR [rbp-0xb0]
   0x555555556a88 <on_button_clicked+668> mov    rsi, rdx
   0x555555556a8b <on_button_clicked+671> mov    rdi, rax
 → 0x555555556a8e <on_button_clicked+674> call   0x5555555561c0 <strcmp@plt>
   ↳  0x5555555561c0 <strcmp@plt+0>   jmp    QWORD PTR [rip+0x2f02]        # 0x5555555590c8 <strcmp@got.plt>
      0x5555555561c6 <strcmp@plt+6>   push   0x19
      0x5555555561cb <strcmp@plt+11>  jmp    0x555555556020
      0x5555555561d0 <gtk_grid_new@plt+0> jmp    QWORD PTR [rip+0x2efa]        # 0x5555555590d0 <gtk_grid_new@got.plt>
      0x5555555561d6 <gtk_grid_new@plt+6> push   0x1a
      0x5555555561db <gtk_grid_new@plt+11> jmp    0x555555556020
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
strcmp@plt (
   $rdi = 0x00007ffff7a2c531 → 0x696c2d6469726700,
   $rsi = 0x00007fffffffadd0 → "flag{86f831a81ae7f9c8c83bf29c6ecce92f}",
   $rdx = 0x00007fffffffadd0 → "flag{86f831a81ae7f9c8c83bf29c6ecce92f}",
   $rcx = 0x0000000000000002
)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "happiness-dist", stopped 0x555555556a8e in on_button_clicked (), reason: BREAKPOINT
[#1] Id 2, Name: "pool-spawner", stopped 0x7ffff6dd79f9 in syscall (), reason: BREAKPOINT
[#2] Id 3, Name: "gmain", stopped 0x7ffff6dcc47f in __GI___poll (), reason: BREAKPOINT
[#3] Id 4, Name: "gdbus", stopped 0x7ffff6dcc47f in __GI___poll (), reason: BREAKPOINT
[#4] Id 5, Name: "happiness-dist", stopped 0x7ffff6dd79f9 in syscall (), reason: BREAKPOINT
[#5] Id 6, Name: "pool-happiness-", stopped 0x7ffff6dd79f9 in syscall (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555556a8e → on_button_clicked(widget=0x5555556a7ee0, data=0x55555561f680)
[#1] 0x7ffff6fab939 → pop rcx
[#2] 0x7ffff6fc133f → mov r10, QWORD PTR [rbp-0x188]
[#3] 0x7ffff6fc6f06 → g_signal_emit_valist()
[#4] 0x7ffff6fc6fc3 → g_signal_emit()
[#5] 0x7ffff76dac90 → jmp 0x7ffff76dabe3
[#6] 0x7ffff6fab939 → pop rcx
[#7] 0x7ffff6fc133f → mov r10, QWORD PTR [rbp-0x188]
[#8] 0x7ffff6fc6f06 → g_signal_emit_valist()
[#9] 0x7ffff6fc6fc3 → g_signal_emit()
```

> **FLAG: flag{86f831a81ae7f9c8c83bf29c6ecce92f}**

## Revved

Bài này giao diện các kiểu cũng gần giống bài trên nhưng thay vì nhập `username` và `password` thì nó lại nhập `username` và `serial`

![revved_img](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Rev/4afe6189aaea261d141cea6f438124f2.png)

Tiếp tục quăng vô `IDA` và xem hàm `on_button_clicked` ta thấy được rằng bây giờ `username` không phải **admin** nữa mà thay vào đó lại là (hắt cơ)**Hacker**

```cpp
user_serial = strtoull(entered_serial, 0LL, 10);
if ( *(_QWORD *)&len[4] == user_serial && !strcmp(username, "Hacker") )               ---> username == "Hacker"
----------------------------------------------------------------- Mã hóa RC4
{
*(_QWORD *)encrypted_string = 0x193536CC64F19FE1LL;
*(_QWORD *)&encrypted_string[8] = 0x80FAE52F53E26D7LL;
*(_QWORD *)&encrypted_string[16] = 0x53B98F7DFD87A294LL;
*(_QWORD *)&encrypted_string[24] = 0x3C7F91A0516AF712LL;
*(_QWORD *)&encrypted_string[30] = 0xC84F8FF01C3F3C7FLL;
encrypted_length = strlen(encrypted_string);
v50 = encrypted_length;
v19 = alloca(16 * ((encrypted_length + 16) / 0x10));
p_decrypted_string = (char (*)[])&dataa;
RC4((char *)entered_serial, encrypted_string, (unsigned __int8 *)&dataa);
-----------------------------------------------------------------
v20 = gtk_label_get_type();
v21 = g_type_check_instance_cast(result_label, v20);
gtk_label_set_text(v21, p_decrypted_string);
v22 = gtk_label_get_type();
v23 = g_type_check_instance_cast(result_label, v22);
gtk_label_set_selectable(v23, 1LL);
v24 = gtk_label_get_type();
v25 = g_type_check_instance_cast(result_label, v24);
gtk_label_set_line_wrap(v25, 1LL);
v52 = 0LL;
v53 = 0x3FF0000000000000LL;
v54 = 0LL;
v55 = 0x3FF0000000000000LL;
gtk_widget_override_color(result_label, 0LL, &v52);
}
```

Không như bài trước là sử dụng mã hoá xor đơn giản và kiểm tra `username` trước thì bài này lại sử dụng mã hoá [RC4](https://en.wikipedia.org/wiki/RC4) và kiểm tra `serial` và `username` cùng lúc. Sau khi nhập đúng `serial` và `username` thì nó thực hiện giải mã `encrypted_string` bằng mã hoá `RC4` với **key** là `entered_serial` cũng có nghĩa là `serial` của người dùng nhập vào và lưu ở `dataa`.

> RC4((char _)entered_serial, encrypted_string, (unsigned \_\_int8 _)&dataa);

Để giải quyết bài này thì ta phải tìm được `serial` cũng chính là **key** để giải mã flag. Để ý trước khi kiểm tra điều kiện có một dòng gọi hàm `strtoull` và gán cho `user_serial` trông rất khả nghi

> user_serial = strtoull(entered_serial, 0LL, 10);

`strtoull`: Là một hàm chuẩn trong thư viện C, có chức năng chuyển đổi một chuỗi ký tự (được biểu diễn dưới dạng số) thành một số nguyên không dấu kiểu unsigned long long.

Vậy có nghĩa là nếu như `serial` là ký tự chữ cái thì nó sẽ trả về **0** và nếu là chữ số thì sẽ chuyển thành một số nguyên không dấu. Vậy ta có thể chắc chắn rằng `serial` là một số bất kỳ nào đó mà không phải chữ cái :()

> **Thật ra trên thực tế là quăng vô gdb luôn chứ không phân tích như trên =))**

Bây giờ hãy vô gdb và đặt breakpoint tại `0x00005555555568ad <+669>:   cmp    rax,QWORD PTR [rbp-0x80]` tương ứng với `( *(_QWORD *)&len[4] == user_serial` rồi `run`. Sau đó nhập `username` là **Hacker** và `serial` là một số bất kỳ

```assembly
0x000055555555689d <+653>:   call   0x5555555561a0 <strtoull@plt>
0x00005555555568a2 <+658>:   mov    QWORD PTR [rbp-0x80],rax
0x00005555555568a6 <+662>:   mov    rax,QWORD PTR [rbp-0xb8]
0x00005555555568ad <+669>:   cmp    rax,QWORD PTR [rbp-0x80]
0x00005555555568b1 <+673>:   jne    0x555555556a4e <on_button_clicked+1086>
0x00005555555568b7 <+679>:   mov    rax,QWORD PTR [rbp-0x90]
0x00005555555568be <+686>:   lea    rdx,[rip+0x176c]        # 0x555555558031
0x00005555555568c5 <+693>:   mov    rsi,rdx
0x00005555555568c8 <+696>:   mov    rdi,rax
0x00005555555568cb <+699>:   call   0x5555555561c0 <strcmp@plt>
0x00005555555568d0 <+704>:   test   eax,eax
0x00005555555568d2 <+706>:   jne    0x555555556a4e <on_button_clicked+1086>
```

> 0x00005555555568ad <+669>: cmp rax,QWORD PTR [rbp-0x80]

Trong mã `assembly` trên thì `QWORD PTR [rbp-0x80]` là nơi lưu trữ số `serial` mà người dùng đã nhập vào, còn `rax` chứa số serial cần so sánh với số `serial` người dùng nhập. Sử dụng lệnh `p/d $rax` để hiển thị số `serial` cần tìm. Việc còn lại lad nhập `serial` để lấy flag thôi!!!

```shell
$ gdb "revved-dist" --q
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.12
Reading symbols from revved-dist...
gef➤  b* 0x00005555555568ad
Breakpoint 1 at 0x5555555568ad: file revved.c, line 82.
gef➤  r
Starting program: /home/kali/CTF/DDC/Rev/Revved/revved-dist
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[New Thread 0x7ffff5c006c0 (LWP 44264)]
[New Thread 0x7ffff52006c0 (LWP 44265)]
[New Thread 0x7fffefe006c0 (LWP 44266)]

(revved-dist:44255): Gtk-WARNING **: 03:22:49.595: Theme parsing error: gtk.css:2057:20: '' is not a valid color name

(revved-dist:44255): Gtk-WARNING **: 03:22:49.595: Theme parsing error: gtk.css:2058:16: '' is not a valid color name

(revved-dist:44255): Gtk-WARNING **: 03:22:49.595: Theme parsing error: gtk.css:2534:38: value 34 out of range. Must be from 0.0 to 1.0

(revved-dist:44255): Gtk-WARNING **: 03:22:49.598: Theme parsing error: gtk.css:4993:38: value 34 out of range. Must be from 0.0 to 1.0

(revved-dist:44255): Gtk-WARNING **: 03:22:49.602: Theme parsing error: gtk.css:7646:38: value 34 out of range. Must be from 0.0 to 1.0

(revved-dist:44255): Gtk-WARNING **: 03:22:49.602: Theme parsing error: gtk.css:7785:51: value 34 out of range. Must be from 0.0 to 1.0
[New Thread 0x7fffef4006c0 (LWP 44267)]
[New Thread 0x7fffeea006c0 (LWP 44268)]
Thread 1 "revved-dist" hit Breakpoint 1, 0x00005555555568ad in on_button_clicked (widget=0x5555556a92f0, data=0x5555556208f0) at revved.c:82
82      revved.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xe48eed8a9ff6
$rbx   : 0x00005555555a1ad0  →  0x0000000000000005
$rcx   : 0x0000555555628171  →  0x0000005550003f00
$rdx   : 0x0
$rsp   : 0x00007fffffffad60  →  0x00005555556208f0  →  0x00005555557095d0  →  0x00005555557aee20  →  0x0000000000000002
$rbp   : 0x00007fffffffae30  →  0x0000555555715cc0  →  0x0000000040000002
$rsi   : 0x0
$rdi   : 0xa
$rip   : 0x00005555555568ad  →  <on_button_clicked+669> cmp rax, QWORD PTR [rbp-0x80]
$r8    : 0x1999999999999999
$r9    : 0x0
$r10   : 0x00007ffff6e4cac0  →  0x0000000100000000
$r11   : 0x00007ffff6e4d3c0  →  0x0002000200020002
$r12   : 0x00007fffffffb0c0  →  0x0000003000000018
$r13   : 0x0
$r14   : 0x0
$r15   : 0x00007ffff6fadb60  →  <g_cclosure_marshal_VOID__VOIDv+0> endbr64
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffad60│+0x0000: 0x00005555556208f0  →  0x00005555557095d0  →  0x00005555557aee20  →  0x0000000000000002      ← $rsp
0x00007fffffffad68│+0x0008: 0x00005555556a92f0  →  0x00005555556a0d60  →  0x000055555561b550  →  0x0000000000000003
0x00007fffffffad70│+0x0010: 0x0000000600000006
0x00007fffffffad78│+0x0018: 0x0000e48eed8a9ff6
0x00007fffffffad80│+0x0020: 0x00005555556208f0  →  0x00005555557095d0  →  0x00005555557aee20  →  0x0000000000000002
0x00007fffffffad88│+0x0028: 0x00005555556d1a00  →  0x000055555563c220  →  0x0000555555701b60  →  0x0000000000000004
0x00007fffffffad90│+0x0030: 0x0000555555718a70  →  0x000055555563c220  →  0x0000555555701b60  →  0x0000000000000004
0x00007fffffffad98│+0x0038: 0x000055555569c9c0  →  0x0000555555649df0  →  0x000055555562db60  →  0x0000000000000008
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555689d <on_button_clicked+653> call   0x5555555561a0 <strtoull@plt>
   0x5555555568a2 <on_button_clicked+658> mov    QWORD PTR [rbp-0x80], rax
   0x5555555568a6 <on_button_clicked+662> mov    rax, QWORD PTR [rbp-0xb8]
 → 0x5555555568ad <on_button_clicked+669> cmp    rax, QWORD PTR [rbp-0x80]
   0x5555555568b1 <on_button_clicked+673> jne    0x555555556a4e <on_button_clicked+1086>
   0x5555555568b7 <on_button_clicked+679> mov    rax, QWORD PTR [rbp-0x90]
   0x5555555568be <on_button_clicked+686> lea    rdx, [rip+0x176c]        # 0x555555558031
   0x5555555568c5 <on_button_clicked+693> mov    rsi, rdx
   0x5555555568c8 <on_button_clicked+696> mov    rdi, rax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "revved-dist", stopped 0x5555555568ad in on_button_clicked (), reason: BREAKPOINT
[#1] Id 2, Name: "pool-spawner", stopped 0x7ffff6dd79f9 in syscall (), reason: BREAKPOINT
[#2] Id 3, Name: "gmain", stopped 0x7ffff6dcc47f in __GI___poll (), reason: BREAKPOINT
[#3] Id 4, Name: "gdbus", stopped 0x7ffff6dcc47f in __GI___poll (), reason: BREAKPOINT
[#4] Id 5, Name: "revved-dist", stopped 0x7ffff6dd79f9 in syscall (), reason: BREAKPOINT
[#5] Id 6, Name: "pool-revved-dis", stopped 0x7ffff6dd79f9 in syscall (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555568ad → on_button_clicked(widget=0x5555556a92f0, data=0x5555556208f0)
[#1] 0x7ffff6fab939 → pop rcx
[#2] 0x7ffff6fc133f → mov r10, QWORD PTR [rbp-0x188]
[#3] 0x7ffff6fc6f06 → g_signal_emit_valist()
[#4] 0x7ffff6fc6fc3 → g_signal_emit()
[#5] 0x7ffff76dac90 → jmp 0x7ffff76dabe3
[#6] 0x7ffff6fab939 → pop rcx
[#7] 0x7ffff6fc133f → mov r10, QWORD PTR [rbp-0x188]
[#8] 0x7ffff6fc6f06 → g_signal_emit_valist()
[#9] 0x7ffff6fc6fc3 → g_signal_emit()
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p/d $rax
$1 = 251302521774070
```

![revved_img_1](https://raw.githubusercontent.com/3r0th3r-CC/3r0th3r-CC.github.io/master/source/assets/images/posts/DDC-2024/Tu-Ket/Rev/7a46cd46d7f59d282b9917c47917c905.png)

> **FLAG: flag{388580f7bac0230a0407e7d13b5afa71}**

Cảm ơn các bạn đã đọc bài viết của chúng mình. Vì lúc tụi mình giải có vài challenge quên lưu lại đề cộng với đây là lần đầu tụi mình làm blog với nhau nên sẽ còn thiếu sót. Tụi mình sẽ cố gắng hơn vào lần sau hehe :3
