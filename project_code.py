import geoip2.database
import dpkt
import socket
import boto3
import json

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
    reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
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
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
    try:
        # Returns the city from the ip
        response = reader.city('{}'.format(ip))
        return response.city.name
    except:
        return "None"

def ip_to_array(pcapFile):
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
    # list for country for ip's
    ip_country_tuple = []
    # iterates through each ip
    for x in scr_list:
        # calls city function
        city = geo_city(x)
        # calls country function
        country = geo_country(x)
        # filters for ip's that have at least a city or country location
        if city != "None" and country != "None":
            ip_country_tuple.append([str(x), str(city), str(country)])
        else:
            pass
    return ip_country_tuple

def pcap_to_s3(event, context=None):
    # **generate variables for S3 and DynamoDB clients**
    s3 = boto3.client('s3')
    dynamodb = boto3.client('dynamodb')
    # **get the bucket name and pcap data file name as key**
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = event['Records'][0]['s3']['object']['key']
    # **Dont process if the files does not have a .pcap extn**
    if '.pcap' not in key:
        return 'Please upload .pcap files only.'
    # **download the .pcap file to /tmp folder**
    s3.download_file(bucket, key, '/tmp/' + key)
    # Open the .pcap file to process it, and upload the processed .csv file
    data_tuple = ip_to_array('/tmp/'+key)
    for x in data_tuple:
        ddb_IP = x[0]
        ddb_City = x[1]
        ddb_Country = x[2]
        response = dynamodb.update_item(
            TableName='209-logs',
            Key={
                'source-ip': {'S': ddb_IP},
                'country': {'S': ddb_Country},
            },
            UpdateExpression='ADD City :city',
            ExpressionAttributeValues={
                ':city': {'S': ddb_City}
            },
            ReturnValues="UPDATED_NEW"
        )
        print(response)