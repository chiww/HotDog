# Ho(s)tDog | 使用Splunk做Linux主机安全应急响应

Ho(s)tDog 是一个使用Splunk做linux主机安全应急响应的小框架。

这个框架实现了几个内容：
1. `endpoint`实现了代码与规则分离的主机状态信息获取执行脚本；
2. `server`实现采集数据的解析与输出到Splunk
3. `TA-HotDog.tar.gz`是Splunk的一个App

详细内容请查看 [使用Splunk做Linux主机应急响应](https://chiww.github.com/HotDog/blob/main/doc/how_to_make_security_response_in_splunk.md)

```
此仓库提供的是一个理论demo，如果要在生产环境使用，需要能够看懂python代码，并具备一定动手能力。
```

## 效果展示
**【任务详情】**
![任务详情](https://github.com/chiww/HotDog/blob/main/static/task_info.gif?raw=true)

**【调查面板】**
![调查面板](https://github.com/chiww/HotDog/blob/main/static/investigator3.gif?raw=true)

**【数据钻取】**
![数据钻取](https://github.com/chiww/HotDog/blob/main/static/data_drill.gif?raw=true)

## 系统框架

![系统框架](https://github.com/chiww/HotDog/blob/main/static/splunk_in_arch_2.png?raw=true)


## 食用方法

```
注意：要正确食用，请一定要看完以下说明，根据实际情况修改配置！（有三处IP需要修改，请仔细甄别）
```

### 模块说明：

1. `endpoint`是被调查分析主机本地执行模块，需要将该模块下发到远程主机；
2. `server`是服务器运行模块，运行在服务端，负责对数据进行解析，并将结构化后的数据上传到Splunk.
3. `TA-Hotdog.tar.gz`是Splunk的App，需要预先将该App安装到Splunk上。


### 服务端服务
开启服务端服务，接收主机上传的数据，完成数据结构化解析，并上传到Splunk.
1. 修改`endpoint`目录下`main.py`的`upload_target`为真实服务端主机IP;
2. 进入`server`目录，执行：
`python3 main.py`
启动后在web服务监听`5566`端口(如需监听其他端口，请自行更改)，有两个用途：
1. 供远程主机下载本地的执行模块`endpoint.tar.gz`使用，如果非使用ssh方式，可以忽略，否则请查看`ssh一键下发`相关内容；
2. 同时远端主机执行完采集命令后会将数据使用POST方法将数据上传到该端口。

### Splunk配置
1. 安装`TA-HotDog.tar.gz`App；
![Install TA-HotDog](https://github.com/chiww/HotDog/blob/main/static/install_TA-HotDog.gif?raw=true)
2. 配置一个`2021`端口的TCP采集服务，其中`index`、`sourcetype`配置为`hotdog`，其他参数保持默认即可。详见下图:
![Add Splunk Datasource](https://github.com/chiww/HotDog/blob/main/static/add_splunk_datasource.gif?raw=true)

**注意：**
默认服务端服务和Splunk部署在同一台机器上，如果不是，请修改`server`目录下`main.py`中的`splunk_connect`值。

### ssh一键下发
原理：开启一个web服务，远程主机通过`curl`获取本地执行脚本及规则；执行完成后将数据POST回服务端。

```
PS: 强烈建议在组织内运维平台统对代码适当改造后使用，不推荐使用该SSH方式.
```

1. 修改`endpoint`目录下`main.py`的`upload_target`为真实服务端主机IP;
2. 生成压缩包`endpoint.tar.gz`，并将该压缩包放置`server`目录内:
```
# tar -zcvf endpoint.tar.gz ./endpoint && mv endpoint.tar.gz ./server
```
3. 修改`endpoint_run.sh`中的`curl`的地址为**服务端IP地址**，否则远程主机无法正确下载本地执行模块；
4. 在服务端通过ssh方式远程执行(需要root权限):
```
ssh root@[remote_ip] < endpoint_run.sh
```

## 后记
由于时间仓促，代码多有不完善的地方，还请各位大佬海涵。如有疑问，可以直接通过微信(cweiwei)找到我，谢谢。