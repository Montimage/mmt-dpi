# MMT_QoE demo

[TOC]

------------------


## Overview

MMT_QoE is a software component for rtp video traffic analysis and quality estimation.

MMT_QoE operates with mmtprobe to analyse the video traffic (live or trace) and MMT_Operator to visualize the report.

mmtprobe listens to configuration commands from the MMT_operator on port number 4567.

## Install MMT_QoE 

** Environment **: Ubuntu 12.04 - 32 bits

** Install dependencies **

```sh
sudo sudo apt-get install libmicrohttpd5 tomcat7 postgresql sqlite3 libpcap libxml2 pgadmin3 default-jdk
```

** Download and install MMT_QoE **

```sh
wget  http://www.montimage.com/mmt-probe/downloads/vestel/mmt_pkg.tar.gz
tar -zxvf mmt_pkg.tar.gz
cd mmt_pkg
./install
sudo -u postgres psql postgres
     \password
     linkma
     \q
     pgadmin # (create mmtdb under localhost server)
sudo mv MMT_Operator_QoE.war /var/lib/tomcat7/webapps
```
## Use MMT_QoE

Go to the directory where mmtprobe was installed `/var/mmt_probe` and run mmtprobe with super user privileges.
```sh
cd /var/mmt_probe
sudo ./mmtprobe
```

Start Tomcat if it is not the case. 
```sh
/etc/init.d/tomcat7 restart
```
After every Tomcat startup you need to initialize MMT DB by following the instructions at: [http://localhost:8080/MMT_Operator_QoE/init-mmtdb.htm](http://localhost:8080/MMT_Operator_QoE/init-mmtdb.htm)

Open a firefox and go to: [http://localhost:8080/MMT_Operator_QoE/operator.htm](http://localhost:8080/MMT_Operator_QoE/operator.htm)

From this page you can launch the analysis of a trace file or on a live network interface.

mmtprobe will save the analysis results into sqlite database files under `/var/mmt_probe/db`

mmtprobe will also print the analysis results to the standard output, they will have the following structure:

`[relative timestamp start in seconds; relative timestamp end in seconds]; flow id; IP source; IP destimation; packets nb; data volume in MB; estimated quality index; last observed jitter; nb packets lost; packet loss rate; nb of loss burts; loss burstiness]`

You can follow the links at  [http://localhost:8080/MMT_Operator_QoE/operator.htm](http://localhost:8080/MMT_Operator_QoE/operator.htm)