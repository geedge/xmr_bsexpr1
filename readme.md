# 实验一实验代码文件说明

环境：Ubuntu。运行所需软件：sudo apt install tshark lua lua-cjson。

## make_traffic 实验原始流量搜集
- make_traffic/get_network_data.py : 利用requests库编写的Python语言脚本，运行在设备上，对域名列表中的域名发起HTTP/HTTPS请求
- make_traffic/get_PvNum.py : 从网址之家获取从Alexa中国访问量排名前200的域名的近三月的日均PV（Page View）值的代码
- make_traffic/domain_pv.txt : Alexa中国访问量排名前200的域名及近三月的日均 PV（Page View）值
- make_traffic/Four_VM_devices.txt & make_traffic/Six_Real_devices.JPG ：10台设备的名字，源IP，源MAC。
- make_traffic/cut_pcap_four.lua & make_traffic/cut_pcap_six.lua : 将10台设备的流量从总流量中过滤出来。
- PCAPS：搜集到的10台设备的 60 分钟的流量。

## TCP/IP被动流量操作系统指纹
- satori：satori开源项目的代码
- zardaxt：zardaxt开源项目的代码
- get_fps.py：从satori开源项目和zardaxt开源项目中提取本实验所需的TCP/IP被动流量操作系统指纹库
- fps.txt: 提取到的指纹库

## 流量特征提取
- extract_feature.lua ：按照数据包为单位提取流量特征
- make_features.py：调用extract_feature.lua，构造实验负样本流量，即非共享接入 IP 的流量（将搜集到的每台设备的 60 分钟的流量按照每份流量持续时长分别为 1、2、3、4、5 分钟均等的分为 60、30、20、15、12 小份，共构造了 600、300、200、150、120 小份流量作为实验负样本流量。）
  - 构造得到的负样本流量存储在 SUB_FEATUREs 文件夹中

## 实验算法实现（论文中算法5，6，7）
detection.py，其中
- dect_windows函数：论文中算法 7 
- dect_linux函数：论文中算法 5 
- dect_XNU函数：论文中算法 6 
- dection函数 & dection_sip函数：两个函数都实现了论文中图3.3所示的算法，dection函数对负样本进行检测，dection_sip函数首先构造正样本（将负样本流量两两组合、并按照捕获时间将报文重新排序，从而获得实验正样本流量即共享接入IP的流量），然后dection_sip函数再对对正样本流量进行检测。
- dect_db1函数：基于全局 IPID 的对比实验的方法（Bellovin [9]提出的方法）
- dect_db2函数：基于全局 TCP TimeStamp 的对比实验的方法（Wicherski 等 [6]提出的方法）

# 实验一代码运行说明

1. 运行 get_fps.py 得到TCP/IP被动流量操作系统指纹库
2. 运行make_features.py，构造实验负样本流量。
3. 再运行detection.py，输出论文中表 3.8 所示的实验结果