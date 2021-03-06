如何在Ubuntu 16.04上安装Elastic Stack日志分析系统
----------------------------------

在本教程中，我将向您展示如何在双个Ubuntu 16.04服务器上安装和配置Elastic Stack，用于监控服务器日志以及如何插入...

**Elasticsearch**是基于Lucene开发的开源搜索引擎，由java开发。 它提供了一个分布式和多租户全文搜索引擎，其中包含HTTP Dashboard Web界面（Kibana）和JSON文档方案。 Elasticsearch是一个可扩展的搜索引擎，可用于搜索所有类型的文档，包括日志文件。 弹性搜索是“弹性”或ELK的核心。

**Logstash**是一个用于管理系统事件和日志的开源工具。 它提供实时流水线来收集数据。 Logstash将收集日志或数据，将所有数据转换为JSON文档，并将其存储在Elasticsearch中。

**Kibana**是Elasticsearch的数据可视化界面。 Kibana提供了一个漂亮的仪表板（Web界面），它允许您自己管理和可视化所有Elasticsearch的数据。 它不仅美丽，而且强大。

在本教程中，我将向您展示如何在单个Ubuntu 16.04服务器上安装和配置弹性，以监控服务器日志，以及如何使用Ubuntu 16.04和CentOS 7操作系统在客户端PC上安装“弹性Beats”。

**前提条件**

*   Ubuntu 16.04 64位服务器，内存为4GB，主机名为elk-master
*   Ubuntu 16.04 64位客户端，4GB RAM，主机名 - elk-slave
*   CentOS 7 64位客户端，1GB RAM，主机名 - elk-client（生产机器）

**elk在master安装，复制安装好的elk机器为slave，slave关闭其他服务,只开启elasticsearch 与master组成集群.**

第1步 - 安装Java
------------

弹性栈部署需要Java。 Elasticsearch需要Java 8.建议使用Oracle JDK 1.8。 我们将从PPA存储库安装Java 8。

安装新软件包**“python-software-properties”** ，以便我们可以使用apt命令轻松添加新的存储库。
```bash
sudo apt-get update  
sudo apt-get install -y python-software-properties software-properties-common apt-transport-https
```
使用'add-apt-repository'命令添加新的Java 8 PPA存储库，然后更新存储库。
```bash
sudo add-apt-repository ppa:webupd8team/java -y  
sudo apt-get update
```
从PPA webpub8存储库安装Java 8。
```bash
sudo apt-get install -y oracle-java8-installer
```
安装完成后，通过检查Java版本，确保系统上的Java安装正确。
```bash
java -version
```
![](https://fwit.win/wp-content/uploads/2018/11/64d228dc93feada7ce352583efe9bf79.png)

第2步 - 安装和配置弹性搜索
---------------

在此步骤中，我们将安装和配置Elasticsearch。 从弹性存储库安装Elasticsearch并将其配置为在localhost IP上运行。

在安装Elasticsearch之前，将弹性存储库密钥添加到服务器。
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
```
将弹性6.x存储库添加到'sources.list.d'目录。
```bash
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
```
更新存储库并使用下面的apt命令安装Elasticsearch 6.4。
```bash
sudo apt-get update  
sudo apt-get install -y elasticsearch
```
弹性搜索已安装。 现在进入配置目录并编辑弹性配置文件。
```bash
cd /etc/elasticsearch/  
vim elasticsearch.yml
```
master elasticsearch.yml
```
cluster.name: cses
node.name: es-node1
node.master: true  # 意思是该节点为主节点
node.data: false
path:
  logs: /var/log/elasticsearch
  data: /var/lib/elasticsearch
network.host: 10.20.0.142
network.bind_host: 0.0.0.0
network.publish_host: 10.20.0.142
transport.tcp.port: 9300
http.port: 9200
#discovery.zen.ping.unicast.hosts: ["10.20.0.142","10.20.1.67","10.20.0.142:9300"]
discovery.zen.ping.unicast.hosts:
   - 10.20.1.67:9300
   - 10.20.0.142 
discovery.zen.minimum_master_nodes: 1
bootstrap.memory_lock: false
bootstrap.system_call_filter: false
```

slave elasticsearch.yml
```
cluster.name: cses
node.name: es-node2
node.master: false  # 意思是该节点为从节点
path:
  logs: /var/log/elasticsearch
  data: /var/lib/elasticsearch
network.host: 10.20.1.67
network.bind_host: 0.0.0.0
network.publish_host: 10.20.1.67
transport.tcp.port: 9300
http.port: 9200
#discovery.zen.ping.unicast.hosts: ["10.20.0.142","10.20.1.67","10.20.0.142:9300"]
discovery.zen.ping.unicast.hosts:
   - 10.20.0.142:9300
   - 10.20.1.67
discovery.zen.minimum_master_nodes: 1
bootstrap.memory_lock: false
bootstrap.system_call_filter: false
```
通过删除第43行的注释，为Elasticsearch启用内存锁定。我们这样做可以禁用Elasticsearch的交换内存，以避免重载服务器。
```
bootstrap.memory_lock: true
```
在“网络”块中，取消注释network.host和http.port行。
```
network.host: localhost  
http.port: 9200
```
保存文件并退出vim。

现在编辑用于内存锁mlockall配置的elasticsearch服务文件。
```
vim /usr/lib/systemd/system/elasticsearch.service
```
取消注释LimitMEMLOCK行。
```
LimitMEMLOCK=infinity
```
保存文件并退出。

在/ etc / default目录中编辑Elasticsearch的默认配置。
```
vim /etc/default/elasticsearch
```
取消注释第60行，并确保该值为“无限制”。
```
MAX_LOCKED_MEMORY=unlimited
```
保存并退出。

弹性搜索配置已完成。 Elasticsearch将在本地主机IP地址9200端口运行，并通过在Ubuntu服务器上启用mlockall来禁用交换内存。

重新加载Elasticsearch服务文件并使其在启动时运行，然后启动服务。
```bash
sudo systemctl daemon-reload  
sudo systemctl enable elasticsearch  
sudo systemctl start elasticsearch
```
等待一秒弹性搜索运行，然后检查服务器上的打开端口，确保端口9200的“状态”为“LISTEN”。
```bash
netstat -plntu
```
![](https://fwit.win/wp-content/uploads/2018/11/297d812b92226d0ee9a4a6551c53a8b7.png)

然后检查内存锁以确保启用mlockall。 还要检查Elasticsearch是否正在运行以下命令。
```bash
curl -XGET 'localhost:9200/_nodes?filter_path=\*\*.mlockall&pretty'  
curl -XGET 'localhost:9200/?pretty'
```
您将看到以下结果。

![](https://fwit.win/wp-content/uploads/2018/11/77ce12a48b24edbe1276ffad42d841c9.png)

第3步 - 使用Nginx安装和配置Kibana
------------------------

在这一步中，我们将在Nginx Web服务器之后安装和配置Kibana。 Kibana将只监听本地主机IP地址，Nginx作为Kibana应用程序的反向代理。

使用此apt命令安装Kibana：
```bash
sudo apt-get install -y kibana
```
现在编辑kibana.yml配置文件。

vim /etc/kibana/kibana.yml

取消注释server.port，server.hos和elasticsearch.url行。
```
server.port: 5601  
server.host: "localhost"  
elasticsearch.url: "http://localhost:9200"
```
保存文件并退出vim。

添加Kibana在启动时运行并启动它。
```bash
sudo systemctl enable kibana  
sudo systemctl start kibana
```
Kibana将作为节点应用程序运行在端口5601上。
```bash
netstat -plntu
```
![](https://fwit.win/wp-content/uploads/2018/11/2e06a8e4a5f3c379592c2896f827c0a3.png)
Kibana安装完成，现在我们需要安装Nginx并将其配置为反向代理，以便能够从公共IP地址访问Kibana。

接下来，安装Nginx和apache2-utils软件包。
```bash
sudo apt-get install -y nginx apache2-utils
```
Apache2-utils是一个包含与Nginx一起使用的Web服务器的工具，我们将使用htpasswd基本身份验证Kibana。

Nginx已经安装。 现在，我们需要在Nginx站点可用的目录中创建一个新的虚拟主机配置文件。 用vim创建一个新文件'kibana'。

cd /etc/nginx/  
vim sites-available/kibana

粘贴配置下面。
```
server {  
    listen 80;  
   
    server_name elk-stack.co;  
   
    auth_basic "Restricted Access";  
    auth_basic_user_file /etc/nginx/.kibana-user;  
   
    location / {  
        proxy_pass http://localhost:5601;  
        proxy_http_version 1.1;  
        proxy_set_header Upgrade $http_upgrade;  
        proxy_set_header Connection 'upgrade';  
        proxy_set_header Host $host;  
        proxy_cache_bypass $http_upgrade;  
    }  
}
```
保存文件并退出vim

使用htpasswd命令创建新的基本身份验证文件。
```bash
sudo htpasswd -c /etc/nginx/.kibana-user admin  
TYPE YOUR PASSWORD
```
通过在“sites-available”中的kibana文件创建一个符号链接到“sites-enabled”目录来激活kibana虚拟主机。
```bash
ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/
```
测试nginx配置，并确保没有错误，然后添加nginx在启动时运行并重新启动nginx。
```bash
nginx -t  
systemctl enable nginx  
systemctl restart nginx
```
![](https://fwit.win/wp-content/uploads/2018/11/2fafea2339b70f5673a8ce0bd70d71da.png)

第4步 - 安装和配置Logstash
-------------------

在此步骤中，我们将安装和配置Logsatash以将来自客户端的服务器日志与文件捕获集中在一起，然后过滤和转换所有数据（Syslog日志或其他）并将其传输到存储（Elasticsearch）。

使用apt命令安装Logstash 5。
```bash
sudo apt-get install -y logstash
```
使用vim编辑hosts文件。
```bash
vim /etc/hosts
```
添加服务器IP地址和主机名。
```
10.20.0.142 cs-elk
```
保存主机文件并退出编辑器。

现在使用OpenSSL生成新的SSL证书文件，以便客户端可以识别弹性服务器。
```bash
cd /etc/logstash/  
openssl req -subj /CN=elk-master -x509 -days 3650 -batch -nodes -newkey rsa:4096 -keyout logstash.key -out logstash.crt
```
将' **/ CN** '值更改为弹性服务器主机名。

证书文件将在'/ etc / logstash /'目录中创建。

接下来，我们将为logstash创建配置文件。 我们将从filebeat创建一个配置文件'filebeat-input.conf'作为输入文件，syslog-filter.conf用于syslog处理，然后是一个'output-elasticsearch.conf'文件来定义Elasticsearch输出。

转到logstash配置目录，并在'conf.d'目录中创建新的配置文件。
```bash
cd /etc/logstash/  
vim conf.d/filebeat-input.conf
```
输入配置，粘贴配置如下，一个站点日志用一个专用端口收集。
```
input {
  beats {
    port => 5044
    type => cslog
   # ssl => true
   # ssl_certificate => "/etc/logstash/logstash.crt"
   # ssl_key => "/etc/logstash/logstash.key"
  }
  beats {
    port => 5045
    type => bestdealslog
   # ssl => true
   # ssl_certificate => "/etc/logstash/logstash.crt"
   # ssl_key => "/etc/logstash/logstash.key"
  }
  beats {
    port => 5046
    type => clatteranslog
   # ssl => true
   # ssl_certificate => "/etc/logstash/logstash.crt"
   # ssl_key => "/etc/logstash/logstash.key"
  }
  beats {
    port => 5047
    type => nighsleelog
   # ssl => true
   # ssl_certificate => "/etc/logstash/logstash.crt"
   # ssl_key => "/etc/logstash/logstash.key"
  }
}
```
保存并退出。

创建log-filter.conf文件。
```bash
vim conf.d/log-filter.conf
```
粘贴以下配置，用tags标签为条件判断日志类型，启用不同的grok过滤规则。
```
filter {
    if "nginx-access-bestdeals" in [tags] or "nginx-access-cs" in [tags] {
        grok {
                patterns_dir => ["/etc/logstash/patterns/csnginx"]
                match => { "message" => "%{CSNGINXACCESS} \"%{PHPSESSID:PHPSESSID}\""}
                overwrite => ["message"]
        }
        mutate {
                convert => ["status","integer"]
                convert => ["body_bytes_sent","integer"]
                convert => ["request_time","float"]
        }
        geoip {
                source=>"remote_addr"
                fields => ["city_name","country_name","ip","latitude","longitude","location","region_name","timezone"]
                remove_field => ["[geoip][latitude]","[geoip][longitude]"]
        }
        date {
                match => [ "timestamp","dd/MMM/YYYY:HH:mm:ss Z"]
        }
        useragent {
                source=>"http_user_agent"
        }
} else if "nginx-access-clatterans" in [tags] or "nginx-access-nighslee" in [tags]  {
        grok {  
                patterns_dir => ["/etc/logstash/patterns/csnginx"]
                match => { "message" => "%{CSNGINXACCESS}"}
                overwrite => ["message"]
        }
        mutate {
                convert => ["status","integer"]
                convert => ["body_bytes_sent","integer"]
                convert => ["request_time","float"]
        }
        geoip { 
                source=>"remote_addr"
                fields => ["city_name","country_name","ip","latitude","longitude","location","region_name","timezone"]
                remove_field => ["[geoip][latitude]","[geoip][longitude]"]
        }
        date {  
                match => [ "timestamp","dd/MMM/YYYY:HH:mm:ss Z"]
        }
        useragent {
                source=>"http_user_agent"
        }
} else if "nginx-error-bestdeals" in [tags] or "nginx-error-cs" in [tags] or "nginx-error-clatterans" in [tags] or "nginx-error-nighslee" in [tags] {
    grok {
                patterns_dir => ["/etc/logstash/patterns/csnginx"]
                match => { "message" => "%{CSNGINXERROR}"}
                overwrite => ["message"]
        }      

} else if "app-error-bestdeals" in [tags] or "app-error-cs" in [tags] or "app-error-clatterans" in [tags] { 
    grok {
                patterns_dir => ["/etc/logstash/patterns/csnginx"]
                match => { "message" => "%{CSAPPERROR}"}
                overwrite => ["message"]
        }

} else if "php-fpm-bestdeals" in [tags] or "php-fpm-cs" in [tags] or "php-fpm-clatterans" in [tags] or  "php-fpm-nighslee" in [tags] {
    grok {
                patterns_dir => ["/etc/logstash/patterns/csnginx"]
                match => { "message" => "%{CSPHPFPM}"}
                overwrite => ["message"]
        }

}

     if "sys-messages"  in [tags] {
        grok {         
                        match => { "message" => "%{SYSLOGLINE}" }
                        add_field => [ "received_at", "%{@timestamp}" ]
                        add_field => [ "received_from", "%{host}" ]
        }
        date {  
                match => [ "timestamp", "MMM  d HH:mm:ss" ]
        }
        #ruby {
        #        code => "event['@timestamp'] = event['@timestamp'].getlocal"
        #}
}
}
```
我们使用名为“ **grok** ”的过滤器插件来解析log文件。

保存并退出。
创建csnginx自定义grok正则表达式文件，具体参考[Grok正则表达式](https://github.com/logstash-plugins/logstash-patterns-core/tree/master/patterns)

vim /etc/logstash/patterns/csnginx
```
USERNAME [a-zA-Z\.\@\-\+_%]+
PHPSESSID %{DATA}
NGUSER %{NGUSERNAME}
NGINXACCESS %{IPORHOST:clientip} - %{NOTSPACE:remote_user} \[%{HTTPDATE:timestamp}\] \"(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})\" %{NUMBER:response} (?:%{NUMBER:bytes}|-) %{QS:referrer} %{QS:agent} \"%{IPV4:http_x_forwarded_for}\"
CSNGINXACCESS (?:%{IP:http_x_forwarded_for}|-) %{IP:remote_addr} \- (?:%{NOTSPACE:remote_user}|-) \[%{HTTPDATE:timestamp}\]\[%{IPORHOST:host}\]\"%{DATA:request_method} (?:%{URI:http_referer}|-) %{DATA:server_protocol}\" %{NUMBER:status} (?:%{NUMBER:body_bytes_sent}|-)\"(?:%{DATA:http_referer}|-)\" \"%{DATA:http_user_agent}\" \"(?:%{NUMBER:upstream_cache_status}|-)\" \"(?:%{BASE16FLOAT:request_time}|-) (?:%{BASE16FLOAT:upstream_response_time}|-) (?:%{IPORHOST}:%{POSINT}%|%{DATA:upstream}|-)\" \"(?:%{IP:http_cdn_src_ip}|-)\" \"(?:%{IP:http_true_client_ip}|-)\"
#CSNGINXERROR (?<timestamp>%{YEAR}[./]%{MONTHNUM}[./]%{MONTHDAY} %{TIME}) \[%{LOGLEVEL:severity}\] %{POSINT:pid}#%{NUMBER:threadid}\: \*%{NUMBER:connectionid} %{GREEDYDATA:errormessage}, client: %{IP:client}, server: %{GREEDYDATA:server}, request: "(?<httprequest>%{WORD:httpcommand} %{UNIXPATH:httpfile} HTTP/(?<httpversion>[0-9.]*))"(, )?(upstream: "(?<upstream>[^,]*)")?(, )?(host: "(?<host>[^,]*)")?
CSNGINXERROR (?<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[%{DATA:err_severity}\] (%{NUMBER:pid:int}#%{NUMBER}: \*%{NUMBER}|\*%{NUMBER}) %{DATA:err_message}(?:, client: (?<clientip>%{IP}|%{HOSTNAME}))(?:, server: %{IPORHOST:server})(?:, request: "%{WORD:verb} %{URIPATHPARAM:request} HTTP/%{NUMBER:httpversion}")?(?:, upstream: "%{DATA:upstream}")?(?:, host: "%{IPORHOST:host}")?(?:, referrer: "%{URI:referrer}”)?
CSAPPERROR %{TIMESTAMP_ISO8601:timestamp} %{DATA:err_severity}\:(?: Message: %{DATA:Message})(?: {main})
MYTIME %{MONTHDAY}[./-]%{MONTH}[./-]%{YEAR} %{TIME}
CSPHPFPM \[%{MYTIME:timestamp}\]\s+%{LOGLEVEL:severity}:\s+%{GREEDYDATA:errormessage}
CSPHPERROR \[%{MYTIME:timestamp}\s+%{DATA:zone}\]\s+PHP\s+%{LOGLEVEL:severity}:\s+%{GREEDYDATA:errormessage}
CSPHPSLOW \[%{MYTIME:time_local}\]  \[pool %{SSL:pool}\] pid %{SSL:pid}\n%{SS:content}
SSL %{USERNAME}
SS ([a-zA-Z0-9._-]|\s|\[|\]|\=|\/|\(|\)|\:)+
```
nginx日志格式
```
log_format main  '$http_x_forwarded_for $remote_addr - $remote_user [$time_local]'
                      '[$host]'
                      '"$request_method $scheme://$host$request_uri $server_protocol" $status $body_bytes_sent'
                      '"$http_referer" "$http_user_agent" "$upstream_cache_status"'
                      ' "$request_time $upstream_response_time $upstream_addr"'
                      ' "$http_cdn_src_ip" "$http_true_client_ip" "$PHPSESSID" ';

```
具体过滤调试可以使用kibana自带的Grok Debugger调试工具，或者[Grok Debugger](http://grokdebug.herokuapp.com/)(自带梯子)
![](https://fwit.win/wp-content/uploads/2018/11/12a48ef6d780833a8ffa3a849a8c47b9.png)

创建输出配置文件'output-elasticsearch.conf'。

vim conf.d/output-elasticsearch.conf

粘贴以下配置。
```
output {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "logstash-%{tags[0]}-%{+YYYY.MM.dd}"
    }
    stdout { codec => rubydebug }
}
```
保存并退出。

完成此操作后，将logstash添加到启动时启动并启动服务。
```bash
sudo systemctl enable logstash  
sudo systemctl start logstash
```
![](https://fwit.win/wp-content/uploads/2018/11/7e405f54893a59924a0565e804cf7bb4.png)

第5步 - 在Ubuntu客户端上安装和配置Filebeat
------------------------------

以root用户身份连接到服务器。
```bash
ssh root@elk-client1
```
使用scp命令将证书文件复制到客户端。
```bash
scp root@elk-server:/etc/logstash/logstash.crt .
```
编辑hosts文件并添加elk-master IP地址。
```
vim /etc/hosts
```
在文件末尾添加下面的配置。
```
10.20.0.142 cs-elk
```
保存并退出。

现在我们需要将弹性键添加到elk-client1服务器。
```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
```
我们将使用带有https下载传输的弹性存储库，因此我们需要在服务器上安装“apt-transport-https”包。
```bash
sudo apt-get install -y apt-transport-https
```
添加弹性存储库并更新所有Ubuntu存储库。
```bash
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
```
现在使用apt命令安装'filebeat'。
```bash
sudo apt-get install -y filebeat
```
接下来，转到filebeat配置目录并使用vim编辑文件'filebeat.yml'。
```bash
cd /etc/filebeat/  
vim filebeat.yml
```
在路径配置下添加新的日志文件。
```
filebeat.prospectors:
- input_type: log
  enabled: true
  paths:
    - /home/crazysal/logs/nginx/crazysales.access.log
  tags: ["nginx-access-cs"]
- input_type: log
  enabled: true
  multiline.pattern: '^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
  multiline.negate: true
  multiline.match: after
  paths:
    - /home/crazysal/logs/nginx/error.log
  tags: ["nginx-error-cs"]
- input_type: log
  enabled: true
  paths:
    - /var/log/php7.1-fpm.log
  tags: ["php-fpm-cs"]
- input_type: log
  enabled: true
  multiline.pattern: '^(\d{4}-\d{2}-\d{2}[T]\d{2}:\d{2}:\d{2}\+\d{2}:\d{2})'
  multiline.negate: true
  multiline.match: after
  paths:
    - /home/crazysal/crazysales_4/log/errorlog-*.txt
  tags: ["app-error-cs"]
- input_type: log
  paths:
    - /var/log/messages
  tags: ["sys-messages"]


output.logstash:
     # The Logstash hosts
  hosts: ["cs-elk:5044"]
 # ssl.certificate_authorities: ["/etc/filebeat/logstash.crt"]
 # ssl.certificate: "/etc/filebeat/logstash.crt"
 # ssl.key: "/etc/filebeat/logstash.key" 
```
保存并退出。
更详细的配置细节参考[官方文档](https://www.elastic.co/guide/en/beats/filebeat/current/configuring-howto-filebeat.html)

将证书文件移动到filebeat目录。
```bash
mv ~/logstash.crt /etc/filebeat/
```
启动filebeat并将其添加到启动时运行。
```bash
sudo systemctl start filebeat  
sudo systemctl enable filebeat
```
检查服务状态。
```bash
sudo systemctl status filebeat
```
![](https://fwit.win/wp-content/uploads/2018/11/4307b6340c34057b7397bc2656b80b70.png)

第6步 - 在CentOS客户端上安装和配置文件(参考[官方安装方法](https://www.elastic.co/guide/en/beats/filebeat/current/setup-repositories.html))
------------------------

Beats是数据shippers，可以安装在客户端节点上的轻量级代理，将大量数据从客户机发送到Logstash或Elasticsearch服务器。 有4个Beats，“Log Files”为“Filebeat”，“Metrics”为“Metricbeat”，Windows客户端“Event Log”为“Network Data”的“Packetbeat”和“Winlogbeat”。

在本教程中，我将向您展示如何安装和配置“Filebeat”，以通过安全的SSL连接将日志数据发送到logstash服务器。

将证书文件从弹性服务器复制到client1服务器。 登录到client1服务器。
```bash
ssh root@elk-client2
```

使用scp命令复制证书文件。
```bash
scp root@elk-master:/etc/logstash/logstash.crt .  
TYPE elk-server password
```
编辑hosts文件并添加elk-master服务器地址。
```bash
vim /etc/hosts
```
添加master主服务器地址。
```bash
10.20.0.142 cs-elk
```
保存并退出。

接下来，将弹性键导入到elk-client2服务器。
```bash
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
```
将弹性存储库添加到服务器。
```bash
cd /etc/yum.repos.d/  
vim elastic.repo
```
粘贴以下配置。
```
[elastic-6.x]  
name=Elastic repository for 6.x packages  
baseurl=https://artifacts.elastic.co/packages/6.x/yum  
gpgcheck=1  
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch  
enabled=1  
autorefresh=1  
type=rpm-md
```
保存并退出。

使用此yum命令安装filebeat。
```
sudo yum -y install filebeat
```
Filebeat已安装，现在转到配置目录并编辑文件'filebeat.yml'。
```
cd /etc/filebeat/  
vim filebeat.yml
```
```
配置参考上面ubuntu客户端
```
```
tail -f /var/log/filebeat/filebeat
```
![](https://fwit.win/wp-content/uploads/2018/11/46e9a757e3c8dfbad467e665bc4de4b8.png)

第8步 - 测试
--------

打开您的网络浏览器，并访问您在nginx配置中配置的弹性域，我的是'elk-stack.co'，用您的密码输入管理员用户名，然后按Enter键登录Kibana仪表板。
![](https://fwit.win/wp-content/uploads/2018/11/8924885cfc6d138d8458842973b0bb11.png)
创建一个新的默认索引' **filebeat- \**或者 **logstash-\***(本示例是这个，具体看output配置输出格式) '并点击' **创建** '。
![](https://fwit.win/wp-content/uploads/2018/11/b904e7e0671481480da01dcab9083848.png)
默认索引已创建。 如果弹性堆叠上有多个Beats，您可以通过点击“ **星形** ”按钮来配置默认Beats。

![](https://fwit.win/wp-content/uploads/2018/11/650b0c229f154485117dd2846a42f324.png)

转到“ **发现** ”，您将看到elk-client1和elk-client2服务器上的所有日志文件。
![](https://fwit.win/wp-content/uploads/2018/11/ee4e2f16c2b452e7429c736c06002399.png)

来自生产服务器日志的http 500状态码输出示例。

![](https://fwit.win/wp-content/uploads/2018/11/b1f55f0c556a7397571f248f89ced190.png)
还有更多的你可以使用Kibana仪表板，只是试试看！

弹性已安装在Ubuntu 16.04服务器上，文件包已安装在Ubuntu和CentOS客户端服务器上。

参考
--

[https://www.elastic.co/guide/index.html](https://www.elastic.co/guide/index.html)