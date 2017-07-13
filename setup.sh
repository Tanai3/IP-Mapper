#!/bin/sh

apt-get install python3-pyqt4
apt-get install libpcap-dev
pip install geoip2
pip install pcapy

wget geolite.maxmind.com/download/geoip/database/GeoLite2-City.mmdb.gz
mkdir -v GeoIP
mv -v GeoLite2-City.mmdb.gz ./GeoIP
gunzip -v GeoIP/GeoLite2-City.mmdb.gz

