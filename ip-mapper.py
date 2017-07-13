#!/usr/bin/python3
# -*- coding:utf-8 -*-
import sys
import os
from PyQt4.QtGui import *       
from PyQt4.QtCore import *
from PyQt4 import QtGui
from PyQt4 import QtCore
import socket
from struct import *
import datetime
import pcapy
import geoip2.database
from geoip2.errors import *
import threading
import time
import subprocess
import gzip
import shutil
import logging


#--------------------------------
# Thread内で1箇所だけupdateを指示している sleepなしにするとここで落ちる可能性あり
# japan->japan問題　=>　日本だけ拡大、もしくは同時に表示
# 同じ通信先が続くと見栄えが悪い
# プロトコルで線の色を変える <= DONE
# 曲線orビーム
# パケットない状態で閉じると終わらない
# 左のラベルをクリックするとその時の状況を反映＋キャプチャストップ
# サブネットに対応する <= Done
#  まずサブネットマスクを取得し、これを8で割る。余りも求める
#  str型で1を8回つなげる、余りの場合は当然1~7回
#  int(str,2)で2進数から10進数へ
#  &でand取る
# マルチキャストに対応する？
# host_sub が不完全 -> ブロードバンド取ればいいが、動作しなくなると怖いのでまた今度
#--------------------------------

item_addr=0
scene_addr=0

class MainWindow(QWidget):
    
    def __init__(self,parent=None):
        self.loopFlag = 0
        self.map_width=763
        self.map_height=507
        self.x_greenwich = 67
        self.y_redline = 296
        self.reader = geoip2.database.Reader('GeoIP/GeoLite2-City.mmdb',['ja'])
        self.worldmapimage = 'world_map.png'
        self.host_addr_v4=""
        self.host_sub=['192','168','0','0']
        self.subnet_mask=""
        self.drawFlag=0
        self.s_cap_res=""
        self.d_cap_res=""
        self.srcLocationX=None
        self.srcLocationY=None
        self.dstLocationX=None
        self.dstLocationY=None
        self.loglist=[]
        self.mypackets=""
        self.__storeNum=1000
        
        tablen='-'*10
        logging.basicConfig(filename='out_pyreshark.log',format=tablen+'%(asctime)s'+tablen+'\n%(message)s',level=logging.DEBUG)
        
        super(MainWindow,self).__init__()
        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start_capture)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_capture)

        self.log_button = QPushButton("Log")
        self.log_button.clicked.connect(self.browse_log)
        
        self.view = QtGui.QGraphicsView()
        self.view.setSizePolicy(QSizePolicy.Ignored,QSizePolicy.Ignored)
        self.scene = QtGui.QGraphicsScene()
        scene_addr=hex(id(self.scene))
        pixmap = QtGui.QPixmap(self.worldmapimage)
        self.item = QtGui.QGraphicsPixmapItem(pixmap)
        item_addr=hex(id(self.item))
        self.scene.addItem(self.item)
        self.scene.addLine(0,self.y_redline,self.map_width,self.y_redline,QPen(Qt.red))
        self.scene.addLine(self.x_greenwich,0,self.x_greenwich,self.map_height,QPen(Qt.blue))
        self.scene.addLine(370,0,370,self.map_height,QPen(Qt.black)) #japan_x
        self.scene.addLine(0,213,self.map_width,213,QPen(Qt.black)) #japan_y
        self.view.setScene(self.scene)

        line="-"*50
        self.label1 = QtGui.QLabel("")
        self.label2 = QtGui.QLabel("")
        self.label3 = QtGui.QLabel("")
        self.label4 = QtGui.QLabel("")
        self.label5 = QtGui.QLabel("")
        self.exampleLabel = QtGui.QLabel("プロトコル: 送信元(国名,経度,緯度) \n=> 送信先(国名,経度,緯度)\n"+line)
        
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label1.setFont(font)
        self.label2.setFont(font)
        self.label3.setFont(font)
        self.label4.setFont(font)
        self.label5.setFont(font)
        self.exampleLabel.setFont(font)
        labelLayout = QVBoxLayout()
        labelLayout.addWidget(self.exampleLabel)
        labelLayout.addWidget(self.label1)
        labelLayout.addWidget(self.label2)
        labelLayout.addWidget(self.label3)
        labelLayout.addWidget(self.label4)
        labelLayout.addWidget(self.label5)
        
        buttonLayout = QHBoxLayout()
        buttonLayout.addWidget(self.start_button)
        buttonLayout.addWidget(self.stop_button)
        buttonLayout.addWidget(self.log_button)
        mapLayout = QHBoxLayout()
        mapLayout.addLayout(labelLayout)
        mapLayout.addWidget(self.view)
        mainLayout = QVBoxLayout()
        mainLayout.addLayout(mapLayout)
        mainLayout.addLayout(buttonLayout)
        
        self.setLayout(mainLayout)
        self.resize(1400,500)
        self.setWindowTitle("IP_Mapper")
        self.show()

    def closeEvent(self,event):
        self.loopFlag=0
        with open('./out_pyreshark.log','wb') as f_in:
            subprocess.check_output(": > ./out_pyreshark.log",shell=True)
            
        tablen='-'*40
        for i in range(0,len(self.loglist)):
            logging.debug(self.loglist[i])
            logging.debug(tablen)
        self.compress_log()
        sys.exit(self)
        
    def start_capture(self):
        if self.loopFlag==0:
            self.write_packet()
        self.loopFlag=1
        
    def stop_capture(self):
        self.loopFlag=0
        
    def store_list(self,log):
        self.loglist.append(str(log)+'\n'+str(self.mypackets))
        if(len(self.loglist) > self.__storeNum):
            self.loglist.pop(0)
            
    def compress_log(self):
        with open('./out_pyreshark.log','rb') as f_in:
            with gzip.open('./out_pyreshark.log.gz','wb') as f_out:
                shutil.copyfileobj(f_in,f_out)
                os.remove('./out_pyreshark.log')

    def browse_log(self):
        d = QtGui.QDialog()
        d.resize(500,500)
        d.setWindowTitle('Browse_Log')
        d.setWindowModality(Qt.ApplicationModal)

        textBox = QTextEdit(d)
        font = QtGui.QFont()
        font.setPointSize(14)
        textBox.resize(500,500)
        textBox.setCurrentFont(font)
        with open('./out_pyreshark.log','wb') as f_in:
            subprocess.check_output(": > ./out_pyreshark.log",shell=True)
            
        tablen='-'*40
        for i in range(0,len(self.loglist)):
            textBox.append(self.loglist[i])
            textBox.append(tablen)
            logging.debug(self.loglist[i])
            logging.debug(tablen)
        textBox.isReadOnly()
        
        d.exec_()
    def paintEvent(self,event):
        if(self.drawFlag==1):
            try:
                if (self.srcLocationX != None and self.srcLocationY != None and self.dstLocationX != None and self.dstLocationY != None):
                    self.renderLine(self.srcLocationX,self.srcLocationY,self.dstLocationX,self.dstLocationY)
                else:
                    self.write_ip()
            except:
                self.write_ip()
        self.drawFlag=0
    def initMap(self):
        self.scene.removeItem(self.item)
        self.scene.clear()
        self.scene.addItem(self.item)
        
    def renderLine(self,src_x,src_y,dst_x,dst_y):
        self.initMap()
        ip_protocol = self.s_cap_res.split(':')[0]
        if (ip_protocol=='ICMP'):
            linePen=QPen(Qt.black)
        elif (ip_protocol=='TCP'):
            linePen=QPen(Qt.blue)
        elif (ip_protocol=='UDP'):
            linePen=QPen(Qt.green)
        elif (ip_protocol=='IPv6'):
            linePen=QPen(Qt.red)
        else :
            linePen=QPen(Qt.yellow)
        self.scene.addLine(src_x,src_y,dst_x,dst_y,linePen)
        self.scene.addEllipse(src_x-5,src_y-5,10,10,QPen(Qt.red),QBrush(Qt.red))
        self.scene.addEllipse(dst_x-5,dst_y-5,10,10,QPen(Qt.blue),QBrush(Qt.blue))
        self.write_ip()
        self.update(0,0,1400,500)
        self.scene.update(0,0,self.map_width,self.map_height)

    def setLocation(self,src_x,src_y,dst_x,dst_y):
        self.srcLocationX=src_x
        self.srcLocationY=src_y
        self.dstLocationX=dst_x
        self.dstLocationY=dst_y
        
    def capture_thread(self):
        counter=0
        cap = self.capture_packet(sys.argv)
        while(self.loopFlag):
            (header,packet) = cap.next()
            self.mypackets=""
            (protocol_type,s_addr,d_addr) = self.parse_packet(packet)
            self.s_cap_res = str(protocol_type)+": "+ str(s_addr)+"("+str(self.get_geoip(s_addr)) + ","+str(self.get_geoip_location(s_addr))+")"
            self.d_cap_res = str(d_addr)+"("+str(self.get_geoip(d_addr)) + ","+str(self.get_geoip_location(d_addr))+")"
            if self.get_geoip_location(d_addr) != None and self.get_geoip_location(s_addr) != None:
                srcloc = tuple(self.get_geoip_location(s_addr).split(','))
                dstloc = tuple(self.get_geoip_location(d_addr).split(','))
                srcloc_x = self.mapLocationX(float(srcloc[1]))
                srcloc_y = self.mapLocationY(float(srcloc[0]))
                dstloc_x = self.mapLocationX(float(dstloc[1]))
                dstloc_y = self.mapLocationY(float(dstloc[0]))
                self.setLocation(srcloc_x,srcloc_y,dstloc_x,dstloc_y)
            else:
                self.setLocation(None,None,None,None)
            self.drawFlag=1
            time.sleep(0.01)
            self.update(0,0,1400,500)
            
    def mapLocationX(self,x):
        if x < 0:
            x = 360 + x
        x = x*(self.map_width/360)+self.x_greenwich+10
        if x > self.map_width:
            x = x - self.map_width
        return x
    def mapLocationY(self,y):
        return self.y_redline-2.4*y
    def write_packet(self):
        client_thread = threading.Thread(target=self.capture_thread,args=())
        client_thread.start()
        
    def write_ip(self):
        self.label5.setText(self.label4.text())
        self.label4.setText(self.label3.text())
        self.label3.setText(self.label2.text())
        self.label2.setText(self.label1.text())
        self.label1.setText(self.s_cap_res+" \n=> "+self.d_cap_res)
        self.store_list(self.s_cap_res+" \n=> "+self.d_cap_res)
        
    def get_geoip(self,addr):
        try:
            record = self.reader.city(addr)
            return record.country.name
        except AddressNotFoundError:
            flag = 1
            if(addr.find(':') != -1):
                return None
            addr=str(addr).split('.')
            subnetmask=self.subnet_mask.split('.')
            for i in range(0,4):
                if(int(addr[i]) & int(subnetmask[i]) != int(self.host_sub[i])):
                    flag=0
            if(flag == 1):
                host_addr=self.host_addr_v4.split('.')
                if(addr == host_addr):
                    return "ローカルホスト"
                else:
                    return "同一ネットワーク"
            else:
                return "ローカルアドレス"
        except:
            return None

    def get_geoip_location(self,addr):
        try:
            record = self.reader.city(addr)
            ip_location = str(record.location.latitude) + "," + str(record.location.longitude)
            return ip_location
        except AddressNotFoundError:
            # ホストネットワーク判定          
            flag = 1
            if(addr.find(':') != -1):
                return None
            addr=str(addr).split('.')
            subnetmask=self.subnet_mask.split('.')
            for i in range(0,4):
                if(int(addr[i]) & int(subnetmask[i]) != int(self.host_sub[i])):
                    flag=0
            if(flag == 1):
                return "35,139" #dendai_point
            else:
                return None
        except Exception as e:
            return None
        
    def capture_packet(self,argv):
        device = pcapy.findalldevs()[0]
        cap = pcapy.open_live(device,65536,True,0)
        
        # ホスト判定部------------------------------------------------------------------------------
        self.host_addr_v4 = subprocess.check_output("ip a | grep {0}".format(device),shell=True)
        self.host_addr_v4=str(self.host_addr_v4)
        first = self.host_addr_v4.index("inet")+5
        last = self.host_addr_v4.index("brd")-4
        self.host_addr_v4 = self.host_addr_v4[first:last]

        # サブネットマスクの計算
        self.subnet_mask = subprocess.check_output("ip a | grep {0}".format(device),shell=True)
        self.subnet_mask = str(self.subnet_mask)
        first = self.subnet_mask.index("/")+1
        last = self.subnet_mask.index("brd")
        self.subnet_mask = int(self.subnet_mask[first:last])
        ip_binary=""
        while(self.subnet_mask > 0):
            ip_binary=ip_binary+"1"
            self.subnet_mask=self.subnet_mask-1
        while(len(ip_binary) < 32):
            ip_binary=ip_binary+'0'
        self.subnet_mask = str(int(ip_binary[0:8],2))+"."+str(int(ip_binary[8:16],2))+"."+str(int(ip_binary[16:24],2))+"."+str(int(ip_binary[24:32],2))
        # ------------------------------------------------------------------------------------------
        
        return cap

    def eth_addr (self,a) :
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(chr(a[0])) , ord(chr(a[1])) , ord(chr(a[2])), ord(chr(a[3])), ord(chr(a[4])) , ord(chr(a[5])))
        return b

    #function to parse a packet
    def parse_packet(self,packet) :
        #parse ethernet header
        eth_length = 14
        
        eth_header = packet[:eth_length]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = socket.ntohs(eth[2])
        #Parse IP packets, IP Protocol number = 8
        if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
            ip_header = packet[eth_length:20+eth_length]
        
            iph = unpack('!BBHHHBBH4s4s' , ip_header)
        
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
        
            iph_length = ihl * 4
        
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);
        
        
            #TCP protocol
            if protocol == 6 :
                # logging.debug ("TCP protocol")
                t = iph_length + eth_length
                tcp_header = packet[t:t+20]
            
                tcph = unpack('!HHLLBBHHH' , tcp_header)
            
                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
            
                h_size = eth_length + iph_length + tcph_length * 4
                data_size = len(packet) - h_size
            
                data = packet[h_size:]
            
                self.mypackets = 'TCP ' + ' Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length) + 'Data : ' + str(data)
                return "TCP",s_addr,d_addr
        
            #ICMP Packets
            elif protocol == 1 :
                u = iph_length + eth_length
                icmph_length = 4
                icmp_header = packet[u:u+4]
            
                icmph = unpack('!BBH' , icmp_header)
            
                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]
            
                h_size = eth_length + iph_length + icmph_length
                data_size = len(packet) - h_size
            
                data = packet[h_size:]
            
                self.mypackets = 'ICMP '+'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum) + ' Data : ' + str(data)
                return "ICMP",s_addr,d_addr
 
            #UDP packets
            elif protocol == 17 :
                # logging.debug ("UDP protocol")
                u = iph_length + eth_length
                udph_length = 8
                udp_header = packet[u:u+8]
            
                udph = unpack('!HHHH' , udp_header)
            
                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]
            
                h_size = eth_length + iph_length + udph_length
                data_size = len(packet) - h_size
            
                data = packet[h_size:]
            
                self.mypackets = 'UDP '+ 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum) + 'Data : ' + str(data)
                return "UDP",s_addr,d_addr

            else :
                return "Other Protocol="+str(protocol),None,None
        if eth_protocol == 56710 :
            # logging.debug ("IPv6")
            ipv6_header = packet[eth_length:40+eth_length]
            ipv6h = unpack("!HHHBB16s16s",ipv6_header)
            s_addr = socket.inet_ntop(socket.AF_INET6,ipv6h[5])
            d_addr = socket.inet_ntop(socket.AF_INET6,ipv6h[6])
            return "IPv6",s_addr,d_addr
        if eth_protocol == 1544 :
            # logging.debug ("ARP")
            arp_header = packet[eth_length:28+eth_length]
            arph = unpack('!HHBBH6s4s6s4s',arp_header)
            s_addr = socket.inet_ntoa(arph[6])
            d_addr = socket.inet_ntoa(arph[8])
            return "ARP",s_addr,d_addr
        if eth_protocol == 36488:
            return "802.1X",None,None
        else:
            return "UNKNOWN type="+str(eth_protocol),None,None


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    sys.exit(app.exec_())
