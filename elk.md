
如何在Ubuntu 16.04上安装Elastic Stack弹性栈
----------------------------------

在本教程中，我将向您展示如何在单个Ubuntu 16.04服务器上安装和配置Elastic Stack，用于监控服务器日志以及如何插入...

**Elasticsearch**是基于Lucene开发的开源搜索引擎，由java开发。 它提供了一个分布式和多租户全文搜索引擎，其中包含HTTP Dashboard Web界面（Kibana）和JSON文档方案。 Elasticsearch是一个可扩展的搜索引擎，可用于搜索所有类型的文档，包括日志文件。 弹性搜索是“弹性”或ELK的核心。

**Logstash**是一个用于管理系统事件和日志的开源工具。 它提供实时流水线来收集数据。 Logstash将收集日志或数据，将所有数据转换为JSON文档，并将其存储在Elasticsearch中。

Kibana是Elasticsearch的数据可视化界面。 Kibana提供了一个漂亮的仪表板（Web界面），它允许您自己管理和可视化所有Elasticsearch的数据。 它不仅美丽，而且强大。

在本教程中，我将向您展示如何在单个Ubuntu 16.04服务器上安装和配置弹性，以监控服务器日志，以及如何使用Ubuntu 16.04和CentOS 7操作系统在客户端PC上安装“弹性Beats”。

**前提条件**

*   Ubuntu 16.04 64位服务器，内存为4GB，主机名为elk-master
*   Ubuntu 16.04 64位客户端，1 GB RAM，主机名 - elk-client1
*   CentOS 7 64位客户端，1GB RAM，主机名 - elk-client2

第1步 - 安装Java
------------

弹性栈部署需要Java。 Elasticsearch需要Java 8.建议使用Oracle JDK 1.8。 我们将从PPA存储库安装Java 8。

安装新软件包**“python-software-properties”** ，以便我们可以使用apt命令轻松添加新的存储库。

sudo apt-get update  
sudo apt-get install -y python-software-properties software-properties-common apt-transport-https

使用'add-apt-repository'命令添加新的Java 8 PPA存储库，然后更新存储库。

sudo add-apt-repository ppa:webupd8team/java -y  
sudo apt-get update

从PPA webpub8存储库安装Java 8。

sudo apt-get install -y oracle-java8-installer

安装完成后，通过检查Java版本，确保系统上的Java安装正确。

java -version

[![Ubuntu 16.04上的Java版本](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/1.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/1.png)

第2步 - 安装和配置弹性搜索
---------------

在此步骤中，我们将安装和配置Elasticsearch。 从弹性存储库安装Elasticsearch并将其配置为在localhost IP上运行。

在安装Elasticsearch之前，将弹性存储库密钥添加到服务器。

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

将弹性5.x存储库添加到'sources.list.d'目录。

echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list

更新存储库并使用下面的apt命令安装Elasticsearch 5.1。

sudo apt-get update  
sudo apt-get install -y elasticsearch

弹性搜索已安装。 现在进入配置目录并编辑弹性配置文件。

cd /etc/elasticsearch/  
vim elasticsearch.yml

通过删除第43行的注释，为Elasticsearch启用内存锁定。我们这样做可以禁用Elasticsearch的交换内存，以避免重载服务器。

bootstrap.memory\_lock: true

在“网络”块中，取消注释network.host和http.port行。

network.host: localhost  
http.port: 9200

保存文件并退出vim。

现在编辑用于内存锁mlockall配置的elasticsearch服务文件。

vim /usr/lib/systemd/system/elasticsearch.service

取消注释LimitMEMLOCK行。

LimitMEMLOCK=infinity

保存文件并退出。

在/ etc / default目录中编辑Elasticsearch的默认配置。

vim /etc/default/elasticsearch

取消注释第60行，并确保该值为“无限制”。

MAX\_LOCKED\_MEMORY=unlimited

保存并退出。

弹性搜索配置已完成。 Elasticsearch将在本地主机IP地址9200端口运行，并通过在Ubuntu服务器上启用mlockall来禁用交换内存。

重新加载Elasticsearch服务文件并使其在启动时运行，然后启动服务。

sudo systemctl daemon-reload  
sudo systemctl enable elasticsearch  
sudo systemctl start elasticsearch

等待一秒弹簧搜索运行，然后检查服务器上的打开端口，确保端口9200的“状态”为“LISTEN”。

netstat -plntu

[![在Ubuntu 16.04上安装Elasticsearch](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/2.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/2.png)

然后检查内存锁以确保启用mlockall。 还要检查Elasticsearch是否正在运行以下命令。

curl -XGET 'localhost:9200/\_nodes?filter\_path=\*\*.mlockall&pretty'  
curl -XGET 'localhost:9200/?pretty'

您将看到以下结果。

[![安装mlockall启用和弹性搜索](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/3.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/3.png)

第3步 - 使用Nginx安装和配置Kibana
------------------------

(adsbygoogle = window.adsbygoogle || \[\]).push({});

在这一步中，我们将在Nginx Web服务器之后安装和配置Kibana。 Kibana将只监听本地主机IP地址，Nginx作为Kibana应用程序的反向代理。

使用此apt命令安装Kibana：

sudo apt-get install -y kibana

现在编辑kibana.yml配置文件。

vim /etc/kibana/kibana.yml

取消注释server.port，server.hos和elasticsearch.url行。

server.port: 5601  
server.host: "localhost"  
elasticsearch.url: "http://localhost:9200"

保存文件并退出vim。

添加Kibana在启动时运行并启动它。

sudo systemctl enable kibana  
sudo systemctl start kibana

Kibana将作为节点应用程序运行在端口5601上。

netstat -plntu

[![在Ubuntu 16.04上安装Kibana](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/4.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/4.png)

Kibana安装完成，现在我们需要安装Nginx并将其配置为反向代理，以便能够从公共IP地址访问Kibana。

接下来，安装Nginx和apache2-utils软件包。

sudo apt-get install -y nginx apache2-utils

Apache2-utils是一个包含与Nginx一起使用的Web服务器的工具，我们将使用htpasswd基本身份验证Kibana。

Nginx已经安装。 现在，我们需要在Nginx站点可用的目录中创建一个新的虚拟主机配置文件。 用vim创建一个新文件'kibana'。

cd /etc/nginx/  
vim sites-available/kibana

粘贴配置下面。

server {  
    listen 80;  
   
    server\_name elk-stack.co;  
   
    auth\_basic "Restricted Access";  
    auth\_basic\_user\_file /etc/nginx/.kibana-user;  
   
    location / {  
        proxy\_pass http://localhost:5601;  
        proxy\_http\_version 1.1;  
        proxy\_set\_header Upgrade $http\_upgrade;  
        proxy\_set\_header Connection 'upgrade';  
        proxy\_set\_header Host $host;  
        proxy\_cache\_bypass $http\_upgrade;  
    }  
}

保存文件并退出vim

使用htpasswd命令创建新的基本身份验证文件。

sudo htpasswd -c /etc/nginx/.kibana-user admin  
TYPE YOUR PASSWORD

通过在“sites-available”中的kibana文件创建一个符号链接到“sites-enabled”目录来激活kibana虚拟主机。

ln -s /etc/nginx/sites-available/kibana /etc/nginx/sites-enabled/

测试nginx配置，并确保没有错误，然后添加nginx在启动时运行并重新启动nginx。

nginx -t  
systemctl enable nginx  
systemctl restart nginx

[![在Ubuntu 16.04上安装了nginx的Kibana](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/5.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/5.png)

第4步 - 安装和配置Logstash
-------------------

在此步骤中，我们将安装和配置Logsatash以将来自客户端的服务器日志与文件捕获集中在一起，然后过滤和转换所有数据（Syslog）并将其传输到存储（Elasticsearch）。

使用apt命令安装Logstash 5。

sudo apt-get install -y logstash

使用vim编辑hosts文件。

vim /etc/hosts

添加服务器IP地址和主机名。

10.0.15.10 elk-master

保存主机文件并退出编辑器。

现在使用OpenSSL生成新的SSL证书文件，以便客户端可以识别弹性服务器。

cd /etc/logstash/  
openssl req -subj /CN=elk-master -x509 -days 3650 -batch -nodes -newkey rsa:4096 -keyout logstash.key -out logstash.crt

将' **/ CN** '值更改为弹性服务器主机名。

证书文件将在'/ etc / logstash /'目录中创建。

接下来，我们将为logstash创建配置文件。 我们将从filebeat创建一个配置文件'filebeat-input.conf'作为输入文件，syslog-filter.conf用于syslog处理，然后是一个'output-elasticsearch.conf'文件来定义Elasticsearch输出。

转到logstash配置目录，并在'conf.d'目录中创建新的配置文件。

cd /etc/logstash/  
vim conf.d/filebeat-input.conf

输入配置，粘贴配置如下。

input {  
  beats {  
    port => 5443  
    type => syslog  
    ssl => true  
    ssl\_certificate => "/etc/logstash/logstash.crt"  
    ssl\_key => "/etc/logstash/logstash.key"  
  }  
}

保存并退出。

创建syslog-filter.conf文件。

vim conf.d/syslog-filter.conf

粘贴以下配置。

filter {  
  if \[type\] == "syslog" {  
    grok {  
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog\_timestamp} %{SYSLOGHOST:syslog\_hostname} %{DATA:syslog\_program}(?:\\\[%{POSINT:syslog\_pid}\\\])?: %{GREEDYDATA:syslog\_message}" }  
      add\_field => \[ "received\_at", "%{@timestamp}" \]  
      add\_field => \[ "received\_from", "%{host}" \]  
    }  
    date {  
      match => \[ "syslog\_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" \]  
    }  
  }  
}

我们使用名为“ **grok** ”的过滤器插件来解析syslog文件。

保存并退出。

创建输出配置文件'output-elasticsearch.conf'。

vim conf.d/output-elasticsearch.conf

粘贴以下配置。

output {  
  elasticsearch { hosts => \["localhost:9200"\]  
    hosts => "localhost:9200"  
    manage\_template => false  
    index => "%{\[@metadata\]\[beat\]}-%{+YYYY.MM.dd}"  
    document\_type => "%{\[@metadata\]\[type\]}"  
  }  
}

保存并退出。

完成此操作后，将logstash添加到启动时启动并启动服务。

sudo systemctl enable logstash  
sudo systemctl start logstash

[![在Ubuntu 16.04上安装和配置Logstash](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/6.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/6.png)

第5步 - 在Ubuntu客户端上安装和配置Filebeat
------------------------------

(adsbygoogle = window.adsbygoogle || \[\]).push({});

以root用户身份连接到服务器。

ssh root@elk-client1

使用scp命令将证书文件复制到客户端。

scp root@elk-server:/etc/logstash/logstash.crt .

编辑hosts文件并添加elk-master IP地址。

vim /etc/hosts

在文件末尾添加下面的配置。

10.0.15.10 elk-master

保存并退出。

现在我们需要将弹性键添加到elk-client1服务器。

wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

我们将使用带有https下载传输的弹性存储库，因此我们需要在服务器上安装“apt-transport-https”包。

sudo apt-get install -y apt-transport-https

添加弹性存储库并更新所有Ubuntu存储库。

echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list  
sudo apt-get update

现在使用apt命令安装'filebeat'。

sudo apt-get install -y filebeat

接下来，转到filebeat配置目录并使用vim编辑文件'filebeat.yml'。

cd /etc/filebeat/  
vim filebeat.yml

在路径配置下添加新的日志文件。

  paths:  
    - /var/log/auth.log  
    - /var/log/syslog

将文档类型设置为“syslog”。

document-type: syslog

通过向行添加注释来禁用弹性搜索输出。

#-------------------------- Elasticsearch output ------------------------------  
#output.elasticsearch:  
  # Array of hosts to connect to.  
\#  hosts: \["localhost:9200"\]

启用logstash输出，取消注释配置并更改值如下。

output.logstash:  
  # The Logstash hosts  
  hosts: \["elk-master:5443"\]  
  bulk\_max\_size: 2048  
  ssl.certificate\_authorities: \["/etc/filebeat/logstash.crt"\]  
  template.name: "filebeat"  
  template.path: "filebeat.template.json"  
  template.overwrite: false

保存并退出。

将证书文件移动到filebeat目录。

mv ~/logstash.crt /etc/filebeat/

启动filebeat并将其添加到启动时运行。

sudo systemctl start filebeat  
sudo systemctl enable filebeat

检查服务状态。

sudo systemctl status filebeat

[![在Ubuntu 16.04客户端上安装Filebeat](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/7.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/7.png)

第6步 - 在CentOS客户端上安装和配置文件
------------------------

Beats是数据shippers，可以安装在客户端节点上的轻量级代理，将大量数据从客户机发送到Logstash或Elasticsearch服务器。 有4个Beats，“Log Files”为“Filebeat”，“Metrics”为“Metricbeat”，Windows客户端“Event Log”为“Network Data”的“Packetbeat”和“Winlogbeat”。

在本教程中，我将向您展示如何安装和配置“Filebeat”，以通过安全的SSL连接将日志数据发送到logstash服务器。

将证书文件从弹性服务器复制到client1服务器。 登录到client1服务器。

ssh root@elk-client2

使用scp命令复制证书文件。

scp root@elk-master:/etc/logstash/logstash.crt .  
TYPE elk-server password

编辑hosts文件并添加elk-master服务器地址。

vim /etc/hosts

添加麋鹿主服务器地址。

10.0.15.10 elk-master

保存并退出。

接下来，将弹性键导入到elk-client2服务器。

rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

将弹性存储库添加到服务器。

cd /etc/yum.repos.d/  
vim elastic.repo

粘贴以下配置。

\[elastic-5.x\]  
name=Elastic repository for 5.x packages  
baseurl=https://artifacts.elastic.co/packages/5.x/yum  
gpgcheck=1  
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch  
enabled=1  
autorefresh=1  
type=rpm-md

保存并退出。

使用此yum命令安装filebeat。

sudo yum -y install filebeat

Filebeat已安装，现在转到配置目录并编辑文件'filebeat.yml'。

cd /etc/filebeat/  
vim filebeat.yml

在路径第21行，添加一些新的日志文件，我们将在这里添加两个文件：ssh的'/ var / log / secure'和服务器日志的'/ var / log / messages'。

  paths:  
    - /var/log/secure  
    - /var/log/messages

在第26行添加一个新配置，将文件类型定义为“syslog”。

document-type: syslog

默认情况下，filebeat使用弹性搜索作为输出。 在本教程中，我们将其更改为logshtash。 通过向行83和85添加注释来禁用弹性搜索输出。

禁用弹性搜索输出。

#-------------------------- Elasticsearch output ------------------------------  
#output.elasticsearch:  
  # Array of hosts to connect to.  
\#  hosts: \["localhost:9200"\]

现在添加新的logstash输出配置，取消注释logstash输出配置，并将所有值更改为下面配置中显示的值。

output.logstash:  
  # The Logstash hosts  
  hosts: \["elk-master:5443"\]  
  bulk\_max\_size: 2048  
  ssl.certificate\_authorities: \["/etc/filebeat/logstash.crt"\]  
  template.name: "filebeat"  
  template.path: "filebeat.template.json"  
  template.overwrite: false

保存并退出。

添加文件开始启动时启动它。

sudo systemctl enable filebeat  
sudo systemctl start filebeat

现在，您可以检查并查看文件捕获日志文件以确保它正确运行。

tail -f /var/log/filebeat/filebeat

[![在CentOS 7客户端服务器上安装Filebeat](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/8.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/8.png)

第8步 - 测试
--------

(adsbygoogle = window.adsbygoogle || \[\]).push({});

打开您的网络浏览器，并访问您在nginx配置中配置的弹性域，我的是'elk-stack.co'，用您的密码输入管理员用户名，然后按Enter键登录Kibana仪表板。

[![登录到弹性kibana仪表板](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/9.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/9.png)

创建一个新的默认索引' **filebeat- \*** '并点击' **创建** '。

[![在Kibana仪表板上创建第一个索引文件](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/10.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/10.png)

默认索引已创建。 如果弹性堆叠上有多个Beats，您可以通过点击“ **星形** ”按钮来配置默认Beats。

[![Filebeat索引创建为默认索引](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/11.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/11.png)

转到“ **发现** ”，您将看到elk-client1和elk-client2服务器上的所有日志文件。

[![从elk-client1和elk-client2服务器发现所有日志](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/12.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/12.png)

来自elk-client1服务器日志的无效ssh登录的JSON输出示例。

[![用于ssh的示例日志文件在elk-client1服务器上登录失败](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/13.png)](https://www.howtoing.com/wp-content/uploads/images/how-to-install-elastic-stack-on-ubuntu-16-04/big/13.png)

还有更多的你可以使用Kibana仪表板，只是试试看！

弹性已安装在Ubuntu 16.04服务器上，文件包已安装在Ubuntu和CentOS客户端服务器上。

参考
--

[https://www.elastic.co/guide/index.html](https://www.elastic.co/guide/index.html)

