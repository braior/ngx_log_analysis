# ngx_log_analysis


ip数据库(GeoLite2-City.mmdb)可以在下面网站获取,有免费和付费:
https://dev.maxmind.com/geoip/geoip2/geolite2/

编译产生二进制文件：
go build

查看运行参数：
.\ngx_log_analysis.exe -h
Usage of loganalysis:
  -dir string
        report log
  -path string
        access log

生成测试结果：
.\ngx_log_analysis.exe -path .\access.log

说明： 模板中的目标地址，地图选型可以自己修改模板来指定