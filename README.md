# BlankBuster V1.0
BlankBuster 是一款由python开发的图形化暴力破解工具，旨在进行渗透测试和安全评估。支持多种协议，允许用户通过尝试使用用户名和密码列表进行身份验证来测试各种服务的安全性。
## 前言
平常在靶机练习时常常要用各种工具进行弱口令漏洞检测，因为嫌麻烦索性自己搞了一个，本项目中大多数代码都是由AI生成的，但是还算好用

## 特性
多协议支持：支持 SSH、FTP、MySQL、Telnet、SMTP、MSSQL、PostgreSQL、SMB 和 RDP 协议。


全自动扫描（弱口令一把梭）：使用 Nmap 自动扫描开放服务并尝试进行暴力破解。


用户友好的界面：基于 Tkinter 构建，提供清晰直观的用户体验。


结果管理：以树形视图显示结果，支持过滤、复制和导出结果。


字典管理：允许用户加载自定义的用户名和密码字典进行暴力破解尝试。


进度跟踪：实时显示进度和成功率。
## 图形化界面展示
![](https://github.com/user-attachments/assets/0de64672-49b3-4312-8cb1-48fc60a66533)

![](https://github.com/user-attachments/assets/2e218942-0fb8-410a-a143-905d66e3423a)
支持一把梭，nmap探测开放端口和服务，然后映射到界面服务选择，又创建队列进行逐个爆破检测。
## 需求
Python 3.x
所需库请看requirements.txt
## 安装
克隆此仓库：

git clone https://github.com/leglessbirds/blankbuster.git


cd BlankBuster

安装所需的 Python 库：
pip install -r requirements.txt
确保已安装 Nmap，并将其添加到系统路径中。

## 使用方法
运行程序：


python BlankBuster.py


在界面中输入目标 IP 地址、选择协议、输入端口、加载用户名和密码字典。

点击“开始”按钮开始扫描。

查看扫描结果，并可选择导出或复制结果。

## 注意事项
本工具仅用于合法的渗透测试和安全评估，请确保在获得授权的情况下使用。
使用暴力破解可能会导致目标服务被锁定或触发安全警报，请谨慎操作。
## 贡献
欢迎任何形式的贡献！如果您有建议或发现了问题，请提交问题或拉取请求。
## 结尾
第一个小工具，感谢大家点个小星星

本人公众号欢迎大家来关注


![](https://github.com/user-attachments/assets/95183c55-94e9-4a95-946e-91099ee65559)



