from scapy.all import *
from scapy.layers.inet import *
import time
from web3 import Web3
import socket
import hashlib
import requests
from lxml import etree
import scapy.layers.http as http
import json
# 开启新的线程
class MyThread(threading.Thread):
    # *****************************************************************************************************
    def __init__(self):
        threading.Thread.__init__(self)

    # *****************************************************************************************************
    def run(self):
        tool = Tool()
        app, web3 = tool.connectChain()
        # place = tool.get_place()
        place = "河南"
        user = tool.get_user()
        while 1:
            time.sleep(1)
            keys = dict_info.keys()
            # temp = {}
            for i in list(keys):
                # 如果发现会话已经五秒钟没有继续了，那么将该会话从字典中删除并上传，否则就减一
                if dict_info[i][0] == 0:
                    # 将所有已经归零的会话流，都加入到一个字典里面，等待上传。
                    # temp[i] = dict[i]
                    # 将会话对应的详情分离出来，并上传
                    data = dict_info[i][7]
                    nums = []
                    for j in range(7):
                        nums.append(dict_info[i][j])
                    self.uploadInfo(i, nums, app, web3, place, user,data)
                    del dict_info[i]
                else:
                    if dict_info[i][0] != 0:
                        dict_info[i][0] -= 1

    # 上传数据到区块链上 ***********************************************************************************
    def uploadInfo(self, i, list, app, web3, place, user, data):
        print("已经结束的会话************************************************************************")
        print(i)
        print(list)
        print(data)

        # 创建一个新账户,拿到他的合约地址
        # print(web3.eth.account.create("123").address)
        # 执行合约里面的set函数
        app.functions.store(i, list, place, user, data).transact({'from': web3.eth.accounts[0]})
        print(app.functions.getAllNums().call())
        print(web3.eth.blockNumber)


class Tool():
    # *****************************************************************************************************
    contract_abi = [
    {
      "inputs": [],
      "stateMutability": "nonpayable",
      "type": "constructor"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "_quinTuple",
          "type": "string"
        },
        {
          "internalType": "uint256[]",
          "name": "_nums",
          "type": "uint256[]"
        },
        {
          "internalType": "string",
          "name": "place",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "user",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "data",
          "type": "string"
        }
      ],
      "name": "NewTraffic",
      "type": "event"
    },
    {
      "inputs": [],
      "name": "trafficIndex",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "_quinTuple",
          "type": "string"
        },
        {
          "internalType": "uint256[]",
          "name": "_nums",
          "type": "uint256[]"
        },
        {
          "internalType": "string",
          "name": "_place",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "user",
          "type": "string"
        },
        {
          "internalType": "string",
          "name": "_data",
          "type": "string"
        }
      ],
      "name": "store",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    },
    {
      "inputs": [],
      "name": "getAllNums",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    },
    {
      "inputs": [
        {
          "internalType": "string",
          "name": "user",
          "type": "string"
        }
      ],
      "name": "getUserNums",
      "outputs": [
        {
          "internalType": "uint256",
          "name": "",
          "type": "uint256"
        }
      ],
      "stateMutability": "view",
      "type": "function"
    }
  ]

    def connectChain(self):
        # 在这里连接区块链
        web3 = Web3(Web3.HTTPProvider("http://localhost:8545"))
        # 实例化一个已经部署的合约
        tx_receipt = web3.eth.waitForTransactionReceipt(
            '0xeb7ad806d61cae3ea09c53c53637dfa3bb098a899e6722480b8b923b54704262')
        # 准备调用合约的方法
        contract_abi = self.contract_abi
        app = web3.eth.contract(address=tx_receipt.contractAddress, abi=contract_abi)
        return app, web3

    # *****************************************************************************************************
    def get_user(self):
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
        data = ":".join([mac[e:e + 2] for e in range(0, 11, 2)])
        m = hashlib.md5()
        m.update(data.encode("utf8"))
        return m.hexdigest()

    def get_place(self):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36'
        }
        res = requests.get("http://ip.chinaz.com/")
        # print(res.text)
        x_data = etree.HTML(res.content)
        #
        ip = x_data.xpath('//dl[@class="IpMRig-tit"]/dd/text()')[1]
        addr = ip.split(" ")[0]
        # ip =x_data.xpath('//dd[@class="fz24"]/text()')
        return addr


class Capture():
    # *****************************************************************************************************
    def start(self):
        load_layer("tls")
        load_layer("SSDP")
        load_layer("http")
        sniff(prn=self.pkt_callback, count=1000)

    # *****************************************************************************************************
    def pkt_callback(self, packet):
        # 获取packet里面的协议名字
        # info = packet.show()

        info = ""
        # 获取五元组
        if packet.haslayer("ARP"):
            arp = packet.sprintf("{ARP:%ARP.psrc%-> %ARP.pdst% -> ARP}")
            # print(arp.strip())
        if packet.haslayer("IP"):
            ipsrc = packet.sprintf("{IP:%IP.src%}").strip()
            ipdes = packet.sprintf("{IP:%IP.dst%}").strip()
            proto = packet.sprintf("{IP:%IP.proto%}").strip()
            info += ipsrc + "#"
            info += ipdes + "#"
            info += proto + "#"

        if packet.haslayer("IPv6"):
            ipv6src = packet.sprintf("{IPv6:%IPv6.src%}").strip()
            ipv6des = packet.sprintf("{IPv6:%IPv6.dst%}").strip()
            proto = packet.sprintf("{IPv6:%IPv6.nh%}").strip()
            info += ipv6src + "#"
            info += ipv6des + "#"
            info += proto + "#"

        if packet.haslayer("UDP"):
            sport = packet.sprintf("{UDP:%r,UDP.sport%}").strip()
            dport = packet.sprintf("{UDP:%r,UDP.dport%}").strip()
            info += sport + "#"
            info += dport + "#"
            if (sport in "123") | (dport in "123"):
                info += "NTP#"
            elif (sport in "1645") | (dport in "1645"):
                info += "RADIUS#"
            elif (sport in "1900") | (dport in "1900"):
                info += "SSDP#"
                data = packet["Raw"].fields
                data = dict([(x, str(y)) for x, y in data.items()])
                info += str(data) + "#"

            elif (sport in "67") | (dport in "67"):
                info += "DHCP#"
            elif (sport in "53") | (dport in "53"):
                info += "DNS#"
                data = packet["DNS"].fields
                data = dict([(x, str(y)) for x, y in data.items()])
                info += str(data) + "#"

            elif (sport in "161") | (dport in "161"):
                info += "SNMP#"
            elif (sport in "500") | (dport in "500"):
                info += "ipsec#"
            elif (sport in "69") | (dport in "69"):
                info += "TFTP#"
            elif (sport in "1701") | (dport in "1701"):
                info += "L2TP#"
            else:
                info += "未知#"

        if packet.haslayer("TCP"):
            sport = packet.sprintf("{TCP:%r,TCP.sport%}").strip()
            dport = packet.sprintf("{TCP:%r,TCP.dport%}").strip()
            flags = packet.sprintf("{TCP:%r,TCP.flags%}").strip()
            info += sport + "#"
            info += dport + "#"
            if (sport in "110") | (dport in "110"):
                info += "POP3#"
            elif (sport in "143") | (dport in "143"):
                info += "IMAP#"
            elif (sport in "25") | (dport in "25"):
                info += "SMTP#"
            elif (sport in "23") | (dport in "23"):
                info += "Telnet#"
            elif (sport in "1723") | (dport in "1723"):
                info += "PPTP#"
            elif (sport in "80") | (dport in "80"):
                # 当系统中有httprequest和httpresponse的时候，就进行添加
                info += "HTTP#"
                info += flags + "#"
                if packet.haslayer(http.HTTPRequest):
                    data = packet["HTTP Request"].fields
                    data = dict([(x, str(y)) for x, y in data.items()])
                    info += str(data) + "#"
                if packet.haslayer(http.HTTPResponse):
                    data = packet["HTTP Response"].fields
                    data = dict([(x, str(y)) for x, y in data.items()])
                    info += str(data) + "#"


            elif (sport in "21") | (dport in "21"):
                info += "FTP#"
            elif (sport in "20") | (dport in "20"):
                info += "FTP#"
            elif (sport in "443") | (dport in "443"):
                # 如果系统中有tls，那么协议就设置为tls，否则就设置为https
                if packet.haslayer("TLS"):
                    info += "TLS#"
                    info += flags + "#"
                    data = packet["TLS"].fields
                    data = dict([(x, str(y)) for x, y in data.items()])
                    info += str(data) + "#"

                else:
                    info += "HTTPS#"
                    info += flags + "#"
            else:
                info += "未知#"
                info += flags + "#"

        # 获取每个数据包的字节数
        info += str(len(packet)) + "#"
        # 获取每个数据包的捕获时间
        info += str(int(packet.time))
        print(info)
        # 在这里需要对字典中的五元组进行比较，得到这个五元组是新的会话还是已经存在的会话
        self.update_dict(info)

    # 在回调函数里面进行数据包的处理，得到相应的五元组********************************************************************
    def update_dict(self, info):
        # 得到字典中所有的key，与str进行比较，如果存在就加一，不存在就加入设置为10
        # 同时如果用str构建反向的str存在字典中，也是存在，不存在就设置为10
        list_str = info.strip().split("#")
        flag = 0
        # 如果长度为8 那么就是udp
        if len(list_str) > 5:
            str = list_str[0] + " " + list_str[1] + " " + list_str[2] + " " + list_str[3] + " " + list_str[4] + " " + \
                  list_str[5] + " "
            str2 = list_str[1] + " " + list_str[0] + " " + list_str[2] + " " + list_str[4] + " " + list_str[3] + " " + \
                   list_str[5] + " "
            if (list_str[2] == "tcp")|(list_str[2] == "TCP"):
                end = list_str[6]
                if ("F" in end) | ("R" in end):
                    flag = 1  # 结束
                else:
                    flag = 0  # 没结束
        else:
            return ""
        # 在此处进行简化代码,得到所有的包的大小以及捕获的时间
        upORdown = self.checkUpOrDown(list_str[0], list_str[1])
        pktSize = int(list_str[-2])
        pktTime = int(list_str[-1])
        # 根据数组的大小来判断是否有详情
        data = ""
        if (len(list_str) == 9) & (list_str[2] == "udp"):
            data = list_str[-3]
        if (len(list_str) == 10) & (list_str[2] == "tcp"):
            data = list_str[-3]
        # 如果得到的数据包在字典中，而且已经判断是上行还是下行
        if upORdown != -1:  # 如果这个流量既不是上行也不是下行，那么不处理这个流量包
            if str in dict_info:
                # 如果是上行包
                if upORdown == 1:
                    # 如果看到了结束标志
                    if flag == 1:
                        dict_info[str][0] = 3
                    else :
                        dict_info[str][0] += 1
                    dict_info[str][1] += 1
                    # 这里不是+= 因为是字符串不能拼接，所以要转换成数字
                    dict_info[str][2] += pktSize
                    dict_info[str][6] = pktTime
                    dict_info[str][7] += data
                else:
                    if flag == 1:
                        dict_info[str][0] = 3

                    else:
                        dict_info[str][0] += 1
                    dict_info[str][3] += 1
                    # 这里不是+= 因为是字符串不能拼接，所以要转换成数字
                    dict_info[str][4] += pktSize
                    dict_info[str][6] = pktTime
                    dict_info[str][7] += data

            elif str2 in dict_info:
                if upORdown == 1:
                    if flag == 1:
                        dict_info[str2][0] = 3
                    else:
                        dict_info[str2][0] += 1
                    dict_info[str2][1] += 1
                    # 这里不是+= 因为是字符串不能拼接，所以要转换成数字
                    dict_info[str2][2] += pktSize
                    dict_info[str2][6] = pktTime
                    dict_info[str2][7] += data
                else:
                    if flag == 1:
                        dict_info[str2][0] = 3
                    else:
                        dict_info[str2][0] += 1
                    dict_info[str2][3] += 1
                    dict_info[str2][4] += pktSize
                    dict_info[str2][6] = pktTime
                    dict_info[str2][7] += data
            else:
                # 如果该会话不在字典中，那么就将该会话加入，并且时间置为30秒，并且设置开始时间，填入包数和字节数，并且判断是上行还是下行
                # 字典中的val的元素：  持续时间   上行包的数目 上行包的大小 下行包的数目 下行包的大小 开始时间 结束时间   详情
                # 字典的val是一个列表，   0           1         2          3         4         5       6   7
                dict_info[str] = [30, 0, 0, 0, 0, 0, 0, 0]
                # 设置开始的时间
                dict_info[str][5] = pktTime
                # 设置默认的结束时间
                dict_info[str][6] = pktTime
                # 设置详情
                dict_info[str][7] = data
                # 判断是上行还是下行
                # 如果是1就是上行，如果不是1就是下行
                if upORdown == 1:
                    # 是上行就将信息存入val中
                    dict_info[str][1] = 1
                    dict_info[str][2] = pktSize
                else:
                    dict_info[str][3] = 1
                    dict_info[str][4] = pktSize

    # 判断是上行还是下行 ************************************************************************这里有问题需要解决
    def checkUpOrDown(self, sip, dip):
        # 获取本机的所有IP地址
        addrs = socket.getaddrinfo(socket.gethostname(), None)
        for addr in addrs:
            if sip == addr[4][0]:
                return 1
            if dip == addr[4][0]:
                return 0
        return -1


if __name__ == '__main__':
    # 定义一个字典，用来记录所有的五元组信息，以及触发事件
    # 字典中的val的元素：  持续时间   上行包的数目 上行包的大小 下行包的数目 下行包的大小 开始时间 结束时间
    # 字典的val是一个列表，   0           1         2          3         4         5       6
    dict_info = {}
    thread = MyThread()
    thread.start()
    capture = Capture()
    capture.start()

    print("**********************************************************************************")
    for i in dict_info:
        print(i + " " + str(dict_info[i]))
    print(len(dict_info))
