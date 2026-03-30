# jdbc任意文件读取

漏洞同样出现在数据源连接处，支持mysql，postgresql。postgresql不在漏洞版本内

mysql5.1.49似乎不存在反序列化漏洞，试了很多方法都不行，只能写个任意文件读取了