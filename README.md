# TC_packet
  Fetch TCP packet


点击include文件下的start.py文件即可运行


![image](https://github.com/Zzjw527/Fetch-TCPpacket/blob/master/photo.png)

1.1任务要求
收集并统计网络TCP流量
1.1.1任务
设计题目	收集并统计网络TCP流量 ★
已知技术参数和设计要求	1.利用WinPcap（Win32环境下数据包捕获的开发代码函数库）进行网络TCP流量监控。
2.程序完成以下功能：
  （1）利用WinPcap收集流经网卡的数据。
  （2）设置过滤器，只留下TCP数据包。
  （3）按端口号对TCP流量进行统计并显示统计结果。
  （3）向用户提供友好的交互界面。
  （4）用户可以方便地中止或继续TCP流量的统计。
  （5）系统必须对出现的问题或错误做出响应。
  
  Design topics Collect and count network TCP traffic ★ Known technical parameters and design requirements 1. Use WinPcap (a development code function library for packet capture under Win32 environment) to monitor network TCP traffic.
2. The program completes the following functions: (1) Use WinPcap to collect data flowing through the network card.
(2) Set up a filter to leave only TCP packets.
(3) Count the TCP traffic according to the port number and display the statistical results.
(3) Provide users with a friendly interactive interface.
(4) Users can easily stop or continue the statistics of TCP traffic.
(5) The system must respond to problems or errors that occur.

设计内容与步骤	1.回顾开发工具的基本使用方法；
2.学习WinPcap编程的基本方法；
3.TCP流量统计系统框架结构设计；
4.TCP流量统计系统的设计与实现
6.完成课程设计报告
设计工作计划与进度安排	1.学习WinPcap流量统计编程的基本方法                      4小时
2.程序设计基础知识准备                                     8小时
3.TCP流量统计系统框架结构设计                             8小时
4.TCP流量统计系统设计                                    12小时 
5.课程设计报告                                             4小时



系统设计
2.1设计环境
语言：Python
工具：Pycharm
2.2功能设计
TCP流量统计系统框架结构设计
TCP流量统计系统的设计与实现
2.3详细设计
1、收集流经网卡的数据
2、过滤器：按端口号只留下TCP数据包
3、用户交互界面
4、能够随时中止或继续TCP流量统计
5、能对出现的问题或错误做出响应






系统实现
3.1系统的实现
3.1.1系统截图与功能截图
程序界面：左边为抓包记录（可点击查看具体信息），右边为抓包日志
开始统计：


停止统计：

清空：（因为采取多线程抓包所以清空得需线程全停止才进行清空）


双击查看具体TCP包解析:

3.1.2问题/错误响应截图





当程序运行中重复点击开始：

当运行前/中网络断开或连接出现问题（同理其他错误）：



3.1.3流程图


文件夹包含文件

3.1.4具体功能模块和关键代码
过滤器及对TCP流量进行统计：

解包并在交互界面中展示：

判断是否联网和联网是否出现问题：
