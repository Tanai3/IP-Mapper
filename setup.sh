#!/bin/sh

apt-get install -y python3-pyqt4
apt-get install -y libpcap-dev
pip3 install geoip2
pip3 install pcapy

wget geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
mkdir -v GeoIP
mv -v GeoLite2-City.mmdb.gz ./GeoIP
gunzip -v GeoIP/GeoLite2-City.mmdb.gz

