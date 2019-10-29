import geoip2.database
import dpkt
import socket

def readPcap(pcap_file):
    # list for IP's
    src_list = []
    # open pcap file
    f = open(pcap_file, 'rb')
    # pass the file argument to the pcap.Reader function
    pcap = dpkt.pcap.Reader(f)
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            # read the source IP in src
            src = socket.inet_ntoa(ip.src)

            # Print the source and destination IP
            dst = socket.inet_ntoa(ip.dst)

            # save the data
            src_list.append(dst)

        except:
            pass

    return src_list

def geo_country(ip):
    reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
    response = reader.country('{}'.format(ip))
    print(response.country.name)

def geo_city(ip):
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    response = reader.city('{}'.format(ip))
    print(response.city.name)


scr_list = readPcap('test.pcap')
geo_city(scr_list[0])
geo_country(scr_list[0])




