import ipaddress
import os
from csv import DictWriter
from csv import DictReader

### file configs ###

config_file_name = 'firewall_config.csv'
config_field_names = ['chain','protocol','src_ip','dest_ip','dest_port','action']

output_file_name = 'output.csv'
output_field_names = ['chain','protocol','src_ip','dest_ip','src_port','dest_port','status']

external_interface_file_name = 'external_interface.csv'
internal_interface_file_name = 'internal_interface.csv'
input_field_names = ['bit_stream']

### helpers ###

def append_dict_as_row(file_name, dict_of_elem, field_names):
    file_exists = os.path.isfile(file_name)
    with open(file_name, 'a+', newline='') as write_obj:
        dict_writer = DictWriter(write_obj, fieldnames=field_names)
        if not file_exists:
            dict_writer.writeheader()  
        dict_writer.writerow(dict_of_elem)

def ip_bin_to_ip_dot_q(ip_bin):
    if (len(ip_bin) != 32):
        # throw error 
        return
    ip_dot_q = (
        str(int(ip_bin[0:8], 2)) + 
        '.' + 
        str(int(ip_bin[8:16], 2)) + 
        '.' + 
        str(int(ip_bin[16:24], 2)) + 
        '.' + 
        str(int(ip_bin[24:32], 2))
        )
    return ip_dot_q

### classes that function as data structures to store header fields ###

class IP:
    def __init__(self, bit_stream):
        self.version_bin = bit_stream[0:4]
        self.ihl_bin = bit_stream[4:8]
        self.tos_bin = bit_stream[8:16]
        self.total_length_bin = bit_stream[16:32]
        self.id_bin = bit_stream[32:48]
        self.flags_bin = bit_stream[48:52]
        self.frag_offset_bin = bit_stream[52:64]
        self.ttl_bin = bit_stream[64:72]
        self.protocol_bin = bit_stream[72:80]
        self.chksum_bin = bit_stream[80:96]
        self.src_address_bin = bit_stream[96:128]
        self.dest_address_bin = bit_stream[128:160]

        self.ihl_int = int(self.ihl_bin, 2) * 32
        self.total_length_int = int(self.total_length_bin, 2) * 8

        self.options_bin = bit_stream[160:self.ihl_int]
        self.payload = bit_stream[self.ihl_int:self.total_length_int]

        self.src_address_dot_q = ip_bin_to_ip_dot_q(self.src_address_bin)
        self.dest_address_dot_q = ip_bin_to_ip_dot_q(self.dest_address_bin)
        self.src_address = ipaddress.ip_network(self.src_address_dot_q)
        self.dest_address = ipaddress.ip_network(self.dest_address_dot_q)

        self.protocol_int = int(self.protocol_bin, 2)
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        self.protocol_name = self.protocol_map[self.protocol_int]

class UDP:
    def __init__(self, udp_bit_stream):
        self.src_port_bin = udp_bit_stream[0:16]
        self.dest_port_bin = udp_bit_stream[16:32]
        self.length_bin = udp_bit_stream[32:48]
        self.chksum_bin = udp_bit_stream[48:64]

        self.src_port_int = int(self.src_port_bin, 2)
        self.dest_port_int = int(self.dest_port_bin, 2)
        self.length_int = int(self.length_bin, 2) * 8

        self.data = udp_bit_stream[64:self.length_int]

class TCP:
    def __init__(self, tcp_bit_stream):
        self.src_port_bin = tcp_bit_stream[0:16]
        self.dest_port_bin = tcp_bit_stream[16:32]
        self.sequence_number_bin = tcp_bit_stream[32:64]
        self.ack_number_bin = tcp_bit_stream[64:96]
        self.header_length_bin = tcp_bit_stream[96:100]
        self.flags_bin = tcp_bit_stream[100:112]
        self.receive_window_bin = tcp_bit_stream[112:128]
        self.chksum_bin = tcp_bit_stream[128:144]
        self.urg_data = tcp_bit_stream[144:160]

        self.header_length_int = int(self.header_length_bin, 2) * 32

        self.options_bin = tcp_bit_stream[160:self.header_length_int]
        
        self.src_port_int = int(self.src_port_bin, 2)
        self.dest_port_int = int(self.dest_port_bin, 2)

        self.data = tcp_bit_stream[self.header_length_int:]


### fn to filter a given bit stream using firewall rules ###

# takes as input, 
#   i) bit stream 
#   ii) chain <- indicates whether bit stream is from external n/w to internal n/w or vice versa  

def filter(bit_stream, chain):
    ip = IP(bit_stream)

    if ip.protocol_name == 'TCP':
        tp_segment = TCP(ip.payload)
    elif ip.protocol_name == 'UDP':
        tp_segment = UDP(ip.payload)
        
    status = {
        'chain': chain,
        'protocol': ip.protocol_name,
        'src_ip': ip.src_address_dot_q,
        'dest_ip': ip.dest_address_dot_q,
        'src_port': tp_segment.src_port_int,
        'dest_port': tp_segment.dest_port_int,
        'status': 'rejected'
    }

    file_exists = os.path.isfile(config_file_name)
    if file_exists:
        with open(config_file_name, newline='') as read_obj:
            dict_reader = DictReader(read_obj)
            for rule in dict_reader:
                if rule['chain'] == chain:
                    if (
                        (rule['protocol'] == ip.protocol_name) or 
                        (rule['protocol'] == 'IP')
                    ):
                        rule_src_net = ipaddress.ip_network(rule['src_ip'])
                        rule_dest_net = ipaddress.ip_network(rule['dest_ip'])
                        rule_dest_port = rule['dest_port']
                        if(
                            ip.src_address.subnet_of(rule_src_net) and
                            ip.dest_address.subnet_of(rule_dest_net) and
                            (
                                (rule_dest_port == str(tp_segment.dest_port_int)) or 
                                (rule_dest_port == '*')
                            )
                        ):
                            
                            if (rule['action'] == 'REJECT'):
                                status['status'] = 'rejected'
                                break
                            elif (rule['action'] == 'ACCEPT'):
                                status['status'] = 'accepted'
                                break 
    return status



### main ###

op_file_exists = os.path.isfile(output_file_name)
if op_file_exists:
    os.remove(output_file_name)

ext_file_exists = os.path.isfile(external_interface_file_name)
if ext_file_exists:
    with open(external_interface_file_name, newline='') as read_obj:
        dict_reader = DictReader(read_obj)
        for row in dict_reader:
            filter_res = filter(row['bit_stream'], 'INPUT')
            append_dict_as_row(output_file_name, filter_res, output_field_names)

int_file_exists = os.path.isfile(internal_interface_file_name)
if int_file_exists:
    with open(internal_interface_file_name, newline='') as read_obj:
        dict_reader = DictReader(read_obj)
        for row in dict_reader:
            filter_res = filter(row['bit_stream'], 'OUTPUT')
            append_dict_as_row(output_file_name, filter_res, output_field_names)

