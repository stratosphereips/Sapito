#!/usr/bin/env python
# Authors:
# Sebastian Garcia, sebastian.garcia@agents.fel.cvut.cz, eldraco@gmail.com
# Veronica Valeros, vero.valeros@gmail.com, valerver@fel.cvut.cz
# Stratosphere Laboratory, Czech Technical University in Prague

import argparse
import macvendor
from scapy.all import *
from datetime import datetime
from zeroconf import _protocol as zproto
import socket

# TODO: THis may need to be updated.
apple_devices ={
    'macbook': 'MacBook',
    'J208AP': 'iPad Pro (10.5-inch) (iPad7,4)',
    'J321AP': 'iPad Pro (12.9-inch) (3rd generation) Wi-Fi + Cellular model. It has 4 GB RAM and is available with 64, 256 and 512 GB of storage. Its identifier is iPad8,7',
    'J127AP': 'iPad Pro (9.7-inch) (iPad6,3)',
    'J81AP': 'iPad Air 2 (iPad5,3)',
    'J72bAP': 'This is the iPad (6th generation) (iPad7,6)',
    'J71bAP': 'iPad (6th generation) (iPad7,5)',
    'J128AP': 'iPad Pro (9.7-inch) (iPad6,4)',
    'J82AP': 'iPad Air 2 (iPad5,4)',
    'J318AP': 'iPad Pro (11-inch) Wi-Fi + Cellular model. It has 4 GB RAM and is available with 64, 256 and 512 GB of storage',
    'J96AP': 'iPad mini 4 (iPad5,1)',
    'J207AP': 'iPad Pro (10.5-inch) (iPad7,3)',
    '_homekit': 'Apple Homekit',
    'J420AP': 'iPad Pro 12.9-inch (4th generation)'

}

class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    IMPORTANT = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    NORMAL = '\033[8m'

# Store info about the clients
# The format of the clients is: {'MAC': 'name'}
clients = {}

def add_client(shw, srcip, name='unknown'):
    """ Add client to our list"""
    try:
        data = clients[shw]
        if 'unknown' in data['name']:
            data['name'] = name
            clients[shw] = data
    except KeyError:
        data = {}
        data['srcip'] = srcip
        data['name'] = name
        clients[shw] = data

def get_client(shw):
    """ Get the client """
    return clients[shw]

def parse_txt(record):
    if b'Chromecast' in record.text:
        device = 'Chromecast'
        info = None
        new_str = record.text.replace(b'\x03', b'\t').replace(b'\x05', b'\t').replace(b'\x0e', b'\t').replace(b'\x12', b'\t')
        parts = new_str.split(b'\t')
        for part in parts:
            if part.startswith(b'fn='):
                info = part[3:]
                return device, info.decode("utf-8") 
    elif b'MacBook' in record.text:
        device = 'Apple'
        new_str = record.text.replace(b'\x14', b',').replace(b'\x11', b',').replace(b'\x07', b',').replace(b'\x08', b',')
        parts = new_str.split(b',')
        for part in parts:
            if part.startswith(b'model='):
                info = part[6:]
                return device, info.decode("utf-8")
            elif part.startswith(b'am='):
                info = part[3:]
                return device, info.decode("utf-8") 

    # iPads send info in TXT records
    for device_name in apple_devices.keys():
        if device_name in str(record.text):
            device = "Apple"
            info = apple_devices[device_name]
            return device, info

    return record.text, None

def parse_mobdev(mobdev_str):
    parts = mobdev_str.split('.')
    ip_mac, _ = parts[0].split('-')
    mac, ip = ip_mac.split('@')
    return mac, ip, parts[2]
    
def parse_record_types(answer):
    printed = False
    prt_str = ""
    if answer.type == 12:
        # PTR
        alias = answer.alias
        for key, value in apple_devices.items():
            if key in alias:
                prt_str = bcolors.WARNING + f'\tThe model of the {key} is {value}' + bcolors.ENDC
                printed = True
        if '_homekit' in alias:
            prt_str = bcolors.WARNING + f'\tThis host knows the Apple Homekit with id: {alias.split(".")[0]}' + bcolors.ENDC
            printed = True
        elif '_companion-link' in alias:
            # Sometimes the companion-link DO have a name of device...
            if '_companion-link' in alias.split('.')[1]:
                prt_str = bcolors.WARNING + '\tThis host knows about the device named {} that has AirDrop active. And maybe other services from Apple.'.format(alias.split('.')[0]) + bcolors.ENDC
                printed = True
            # Sometimes the companion-link does not have a name of device...
            elif '_companion-link' in alias.split('.')[0]:
                prt_str = bcolors.WARNING + '\tThis host has AirDrop activated.'.format(alias.split('.')[0]) + bcolors.ENDC
                printed = True
            elif 'Elmedia Video Player' in alias and 'airplay' in alias:
                prt_str = '\tAirplay Enabled in this host.'
                printed = True
            elif 'mobdev' in alias:
                try:
                    mac, ip, proto = parse_mobdev(alias)
                    prt_str = bcolors.WARNING + f'\tThis host has a PTR record to an iTunes WiFi Sync service named {answer.name}, on MAC {mac}, and IP {ip} using protocol {proto}' + bcolors.ENDC
                    printed = True
                except:
                    pass
                            
        if not printed:
            prt_str = f'\tAnswer Type: PTR. Name: {answer.name} Alias: {alias}'
        
    elif answer.type ==5:
        # CNAME
        prt_str = f'\tAnswer Type: CNAME. Name: {answer.name}. Rdata to process: {answer.alias}'
    elif answer.type == 16:
        # TXT type
        # TODO: some handling here
        device, info = parse_txt(answer)
        if info is not None:
            prt_str = f'\tAnswer Type: TXT Device: {device} Info: {info}'
        else:
            prt_str = f'\tAnswer Type: TXT Text: {device}'
    elif answer.type == 1:
        # A
        ip = socket.inet_ntoa(answer.address)
        prt_str = bcolors.WARNING + f'\tThe IPv4 address of this device named {answer.name} is {ip}' + bcolors.ENDC
    elif answer.type == 28:
        # AAAA
        ip = socket.inet_ntop(socket.AF_INET6, answer.address)
        prt_str = bcolors.WARNING + f'\tThe IPv6 address of this device named {answer.name} is {ip}' + bcolors.ENDC                    
    elif answer.type == 13:
        # HINFO
        prt_str = f'\tAnswer Type: HINFO. Name: {answer.name}. OS : {answer.os}, CPU: {answer.cpu}'
    elif answer.type == 47:
        # NSEC
        prt_str = f'\tAnswer Type: NSEC. Name: {answer.name}. Rdtypes: {answer.rdtypes}, Next name: {answer.next_name}'
    elif answer.type == 33:
        # SRV
        prt_str = '\tServices Offered in the Answers:\n'
        prt_str += f'\t\tAnswer Type: SRV. Name: {answer.name} Server: {answer.server} Port: {answer.port} Priority: {answer.priority}'

    return prt_str

def do(pkt):
    """
    Do something
    """
    if IP in pkt and UDP in pkt:
        if pkt[UDP].dport == 5353:
            shw = pkt[Ether].src.upper()
            mac_vendor = macvendor.get_all(shw).manuf_long
            srcip = pkt[IP].src
            add_client(shw, srcip)
            UDPlayer = pkt[UDP]
            #len = UDPlayer.len
            if DNS in UDPlayer:
                # DNSlayer = pkt[UDP][DNS]
                # The DNSlayer.fields are:
                #  - length,id,qtype,name,qd,an,ar qr,opcode,
                #    aa,tc,rd,ra,z,ad,cd,rcode,qdcount,ancount,
                #    nscount,arcount
                
                # TODO: Add the timestamp
                inc_packet = zproto.incoming.DNSIncoming(bytes(pkt[UDP].payload), (4, srcip))

                num_questions = inc_packet.num_questions
                num_additional_records = inc_packet.num_additionals
                num_answers = inc_packet.num_answers
                num_auth = inc_packet.num_authorities
                # TODO: Find the Authoritative Nameservers
                if args.debug:
                    print("[Debug]:", inc_packet)
                print(bcolors.HEADER + f"\033[36m{datetime.now()}\033[95m | SrcMAC: \033[36m{shw}\033[95m | Vendor: \033[36m{mac_vendor}\033[95m | SrcIP: \033[36m{srcip}\033[95m | Name: \033[36m{get_client(shw)['name']}\033[95m | Questions: \033[36m{num_questions}\033[95m | Additional Records: \033[36m{num_additional_records}\033[95m | Answers: \033[36m{num_answers}\033[95m | Authoritative Nameservers: \033[36m{num_auth}\033[95m" + bcolors.ENDC)

                #####################
                # Process the questions
                #
                print(bcolors.HEADER + f' > Questions: \033[36m{num_questions}\033[95m' + bcolors.ENDC)
                for question in inc_packet.questions:
                    if args.debug:
                        print(f"\t[Debug] Question: {question}")
                    else:
                        print(f"\t{question.name}")

                #####################
                # Process all the Records
                #
                print(bcolors.HEADER + f' > Answers + Authorities: \033[36m{num_answers+num_auth}\033[95m' + bcolors.ENDC)
                # We will try to parse these answers by type
                # The answers hold also the authorities and the additional records
                answers = inc_packet.answers()
                if len(answers) != (num_answers + num_auth + num_additional_records):
                    print("At least one record was not parsed.")
                if num_answers + num_auth > 0:
                    for answer in answers[:num_answers + num_auth]:
                        if args.debug:
                            print(f"\t[Debug] Record: {answer}")
                        else:
                            print(parse_record_types(answer))
                        

                #####################
                # Process the Additional records
                # 
                print(bcolors.HEADER + f' > Additional Records: \033[36m{num_additional_records}\033[95m' + bcolors.ENDC)
                # Amount of additional records
                if num_additional_records:
                    for record in answers[num_answers+num_auth:]:
                        if args.debug:
                            print(f"\t[Debug] Record: {answer}")
                        else:
                            print(parse_record_types(answer))


# Main
####################
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v',
                        '--verbose',
                        help='Verbosity level. This shows more info about the results.',
                        action='store',
                        required=False,
                        type=int)
    parser.add_argument('-d',
                        '--debug',
                        help='Debugging level. This shows inner information about the flows.',
                        action='store',
                        required=False,
                        type=int)
    parser.add_argument('-r',
                        '--readfile',
                        help='Name of the pcap file to read.',
                        action='store',
                        required=False,
                        type=str)
    parser.add_argument('-i',
                        '--interface',
                        help='Name of the interface to use.',
                        action='store',
                        required=False,
                        type=str)
    parser.add_argument('-f',
                        '--filter',
                        help='Tcpdump style filter to use.',
                        action='store',
                        required=False,
                        type=str)

    args = parser.parse_args()

    # Reload the file of Mac vendors
    macvendor.refresh()

    if args.interface:
        sniff(iface=args.interface, prn=do, store=0, filter=args.filter)
    elif args.readfile:
        sniff(offline=args.readfile,prn=do,store=0, filter=args.filter)
