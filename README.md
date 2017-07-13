# IP-Mapper
setup.shはubuntu用。  
aptとpip3が通れば大丈夫なはず  

* chmod +x setup.sh
* sudo ./setup.sh

それ以外の場合は下記の依存パッケージをインストール。  

* python3-pyqt4
* libpcap-dev
* pcapy
* geoip2

dl_geoip2.sh で必要なipのデータベースは確保できる。
