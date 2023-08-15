# cn_Villain
[![Python](https://img.shields.io/badge/Python-%E2%89%A5%203.6-yellow.svg)](https://www.python.org/) 
<img src="https://img.shields.io/badge/PowerShell-%E2%89%A5%20v3.0-blue">
<img src="https://img.shields.io/badge/Developed%20on-kali%20linux-blueviolet">
[![License](https://img.shields.io/badge/License-CC%20Attr--NonCommercial%204.0-red)](https://github.com/t3l3machus/Villain/blob/main/LICENSE.md)
<img src="https://img.shields.io/badge/Maintained%3F-Yes-96c40f">

汉化自：https://github.com/t3l3machus/Villain/tree/main

## 目的

Villain 是一个高级 C2 框架，可以处理多个 TCP 套接字和基于 HoaxShell 的反向 shell，通过附加功能（命令、实用工具等）增强其功能，并在连接的同级服务器之间共享它们（在不同机器上运行的 Villain 实例）之间的功能。

该框架的主要特点包括：
 - 基于默认、可定制和/或用户定义的负载模板（Windows 和 Linux）生成负载，
 - 动态参与的伪 shell 提示，可以快速在 shell 会话之间切换，
 - 文件上传（通过 http），
 - 自动 http 请求和在会话中执行脚本（有些不稳定），
 - 自动调用 ConPtyShell，在 powershell 反向 shell 会话中以新进程方式获得完全交互式的 Windows shell，
 - 团队聊天，
 - 会话防御者（一种检查用户发出的命令是否存在错误/意外输入，可能导致 shell 挂起的功能）

请查看 [使用指南](https://github.com/t3l3machus/Villain/blob/main/Usage_Guide.md)。

### 视频演示
[2022-11-30] [John Hammond](https://github.com/JohnHammond) 在这个令人难以置信的视频中展示了该工具 -> [youtube.com/watch?v=pTUggbSCqA0](https://www.youtube.com/watch?v=pTUggbSCqA0)  
[2023-03-30] 最新版本演示，由我制作 -> [youtube.com/watch?v=NqZEmBsLCvQ](https://www.youtube.com/watch?v=HR1KM8wrSV8)

:warning: 创建自己的混淆反向 shell 模板，并将默认模板替换为 Villain 实例中的模板，以更好地处理反病毒逃避。如何操作请看这里 📽️ -> [youtube.com/watch?v=grSBdZdUya0](https://www.youtube.com/watch?v=grSBdZdUya0)

**免责声明**：对未经明确许可进行测试的主机使用该工具是违法的。你对使用该工具可能引发的任何麻烦负有责任。

## 预览

![cn1](/img/cn1.png)

![cn1](/img/cn2.png)

## 安装和使用
Villain 已明确在 **kali linux** 上开发和测试。你可以使用 `apt` 安装它：
```
apt install villain
```
你需要以 root 权限运行：
```
villain [-h] [-p PORT] [-x HOAX_PORT] [-n NETCAT_PORT] [-f FILE_SMUGGLER_PORT] [-i] [-c CERTFILE] [-k KEYFILE] [-u] [-q] 
```

如果你想使用最新版本或者更喜欢手动安装：
```
git clone https://github.com/t3l3machus/Villain
cd ./Villain
pip3 install -r requirements.txt
```
你还需要安装 `gnome-terminal`（某些框架命令需要）：
```
sudo apt update && sudo apt install gnome-terminal
```

## 重要说明
1. HoaxShell 植入物现在是可重复使用的，只要它们是由你尝试从受害者的主机回连到的 Villain 实例生成的（合法会话数据保存在磁盘上，并在每次在你的机器上启动 Villain 时加载到内存中）。如果它接收到来自它的信标（例如，因为负载仍在受害者上运行），Villain 也会重新建立会话。你可以使用新的命令 `flee` 退出 Villain 而不终止活动会话。这样，下次你启动它时，如果有来自受害者的活动信标，会话将被重新建立。
2. 兄弟服务器之间的通信使用 AES 加密，以接收兄弟服务器的 ID 作为加密密钥，以本地服务器 ID 的前 16 个字节作为初始化

向量（IV）。在两个兄弟服务器的初始连接握手期间，每个服务器的 ID 以明文交换，这意味着握手可能会被捕获并用于解密兄弟服务器之间的流量。我知道这样做是“脆弱”的。这并不是为了超级安全，因为这个工具被设计用于渗透测试/红队评估，对于这种加密方案应该足够了。
3. 相互连接的 Villain 实例（兄弟服务器）必须能够直接相互到达。我打算添加一个网络路由映射工具，以便兄弟服务器可以使用彼此作为代理，在它们之间实现跨网络通信（某一天）。

## 贡献
拉取请求通常是欢迎的。请记住：我一直在开发新的渗透测试工具，同时也在维护几个现有的工具。我很少接受拉取请求，因为我要么已经有一个项目的计划，要么我评估很难测试和/或维护外部代码。这与一个想法是好还是坏无关，只是太多的工作，而且我也是在开发所有这些工具来自我学习。

项目的某些部分在发布之前被删除，因为我认为它们存在错误或难以维护（在这个早期阶段）。
如果你对一个带有大量代码的附加功能有想法，请在提交拉取请求之前先与我联系，讨论一下是否已经有类似的功能在开发中，以免重复工作。