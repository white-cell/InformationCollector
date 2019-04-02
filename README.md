# InformationCollector
* 针对域名目标收集子域名
* 获取子域名指纹和搜索引擎部分结果
* 通过证书信息在censys挖掘源ip
* 通过子域名判断是否使用cdn挖掘源ip

```
python main.py

 ___          __                                 _    _
|_ _| _ __   / _|  ___   _ __  _ __ ___    __ _ | |_ (_)  ___   _ __
 | | | '_ \ | |_  / _ \ | '__|| '_ ` _ \  / _` || __|| | / _ \ | '_ \   __author__="Jaqen"
 | | | | | ||  _|| (_) || |   | | | | | || (_| || |_ | || (_) || | | |
|___||_| |_||_|   \___/ |_|   |_| |_| |_| \__,_| \__||_| \___/ |_| |_|

  ____         _  _              _
 / ___|  ___  | || |  ___   ___ | |_   ___   _ __
| |     / _ \ | || | / _ \ / __|| __| / _ \ | '__|
| |___ | (_) || || ||  __/| (__ | |_ | (_) || |
 \____| \___/ |_||_| \___| \___| \__| \___/ |_|

Usage: python main.py -i baidu.com 
       python main.py -f host.txt
```
# tips
* pip install bs4
* 42、43行配置censys的key
* 有的网站api需要翻墙，37行可自行配置代理
* 还有很多很棒的接口，但是都会有次数限制，就像censys一个月只能100次

# 输出
* 子域名相关指纹和爬虫信息输出到report目录html文件
* 子域名、源ip输出到history目录txt文件

# 运行
![](https://github.com/white-cell/InformationCollector/blob/master/1.jpg)
![](https://github.com/white-cell/InformationCollector/blob/master/2.jpg)
# 更新
## 2019-04-02
* 修复获取部分title bug
* 调整获取搜索引擎结果正则
* 调整输出报告格式