import geoip2.database
import dpkt
import socket
import pandas as pd

def readPcap(pcap_file):
    """
    Reads pcap file and returns list of ip's
    Args:
        pcap_file: The pcap file you want the ip's to be read from
    Returns: List of source ip's
    """
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
    """
    Uses GeoLite database to find country of source ip
    Args:
        ip: desired ip

    Returns: country ip came from
    """
    # path to the GeoLite database
    reader = geoip2.database.Reader('/Users/jonathan/Desktop/Fall 19/EE209/Project/GeoLite2-Country_20191022/GeoLite2-Country.mmdb')
    try:
        # Returns the country from the ip
        response = reader.country('{}'.format(ip))
        return response.country.name
    except:
        return 'None'

def geo_city(ip):
    """
    Uses GeoLite database to find city of source ip
    Args:
        ip: desired ip
    Returns: city ip came from
    """
    # path to the GeoLite database
    reader = geoip2.database.Reader('/Users/jonathan/Desktop/Fall 19/EE209/Project/GeoLite2-City_20191029/GeoLite2-City.mmdb')
    try:
        # Returns the city from the ip
        response = reader.city('{}'.format(ip))
        return response.city.name
    except:
        return "None"

def ip_to_csv(pcapFile):
    """
    Writes source ip city and country to csv file
    Args:
        pcapFile: pcap file to read from
    Returns: csv file of ip's and their locations
    """
    # gets the list of source ip's from the pcap file
    scr_list = readPcap(pcapFile)
    # list for source ip's
    scr_ip = []
    # list for city's for ip's
    city_list = []
    # list for country for ip's
    country_list = []
    # iterates through each ip
    for x in scr_list:
        # calls city function
        city = geo_city(x)
        # calls country function
        country = geo_country(x)
        # filters for ip's that have at least a city or country location
        if city != "None" and country != "None":
            scr_ip.append(x)
            city_list.append(city)
            country_list.append(country)
        else:
            pass
    # writes the data to a csv file
    df = pd.DataFrame({'IP' : scr_ip, 'City' : city_list, 'Country' : country_list})
    df.to_csv('IP_GeoLocation.csv', encoding='utf-8', index=False)

ip_to_csv('smallFlows.pcap')