﻿# ngx_log_analysis


ip数据库(GeoLite2-City.mmdb)可以在下面网站获取,有免费和付费:
https://dev.maxmind.com/geoip/geoip2/geolite2/

编译产生二进制文件：
go build

查看运行参数：
.\ngx_log_analysis.exe -h

生成测试结果：
.\ngx_log_analysis.exe -path .\access.log

测试结果默认存放在当前目录下的reports下，会以时间戳来区分每次生成的文件，打开index.html便可以预览结果

说明： 模板中的目标地址，地图选型可以自己修改模板来指定
