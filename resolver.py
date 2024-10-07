import socket
from socket import AF_INET, SOCK_DGRAM, SO_REUSEADDR, SOL_SOCKET
import sys
import struct
import re
import random
import helper
import argparse

ROOT_FILE = "named.root"
HOST = 'localhost'
TYPE_NS = 2
TYPE_A = 1

# class ServerExhausted(Exception):
#     "Servers exhausted."
#     pass

def open_root():
    # Loading named.root
    root_servers = []
    with open(ROOT_FILE, "r") as file:
        for line in file:
            if re.search(r'\sA\s', line):
                root_servers.append(line.split()[-1])
    return root_servers

def send_query(query, ip_address, timeout):
    resolver_socket = socket.socket(AF_INET, SOCK_DGRAM)
    resolver_socket.settimeout(timeout)
    try:
        resolver_socket.sendto(query, (ip_address, 53))
        response, _ = resolver_socket.recvfrom(2048)
    except socket.timeout:
        print(f"Error[Timeout]: No response received within {timeout} seconds.")
        print(f"Trying next server...")
        return None
    return response

def get_addtional_ip(addits):
    # Return the first Additional record's RDATA
     for record in addits:
        if record['TYPE'] == TYPE_A:
            return record['RDATA']

def construct_dns_response(ini_data, res_data, question):
    # Parsing initial data and resolved data
    parsed = helper.parse_dns_response(ini_data)
    res_parsed = helper.parse_dns_response(res_data)

    qid = parsed['HEADER']['ID']
    header_section = res_data[:12]
    header_values = struct.unpack('!HHHHHH', header_section)
    flags = header_values[1]

    qtype = question['TYPE']
    qname = question['NAME']
    
    # Initializing the offset to decode the res_data's answer section.
    offset = helper.decode_name(res_data, 12)[1] + 4
    answer_count = 0
    answers = b''

    # Iterating through the resolved data's 'ANSWER' section and constructing the answer section of the response.
    for record in res_parsed['ANSWER']:
        answer_count += 1
        name, name_end = helper.decode_name(res_data, offset)
        answers += helper.encode_dns_address(name)
        answers += res_data[name_end: name_end + 10 + record['RDLENGTH']]
        offset = name_end + 10 + record['RDLENGTH']

    # Putting it all together...
    response = helper.encode_dns_sections([qid, flags, 1, answer_count, 0, 0], [qtype, 1], qname)
    return (response + answers)

def resolve_address(query, server_ip, timeout, root):
    queries = 0
    while True:
        queries += 1
        if queries > 5:
            return None
        print(f"Sending query to {server_ip} ...")
        data = send_query(query, server_ip, timeout)
        print(f"Query sent to {server_ip}")

        # No response received, returning None.
        if data is None:
            return None

        parsed = helper.parse_dns_response(data)
        print(f"Data returned from query {parsed}\n")
        rcode = parsed['HEADER']['RCODE']

        # Error situations
        if (rcode == 2) or (rcode == 5):
            return None
        if (rcode > 0):
            return data
        
        # If there are answers in the response, loop through them.
        if (len(parsed['ANSWER']) > 0):
            for record in parsed['ANSWER']:
                question = parsed['QUESTION'][0]
                # If record type != question type, possibly CNAME or NS
                # which requires further resolution, therefore
                # recursively resolve the target IP address and construct the final response.
                if (question['TYPE'] != record['TYPE']): # CNAME or NS, find ip
                    rd = False
                    if ('rd' in parsed['HEADER']['FLAGS']):
                        rd = True
                    resolved_data = resolve_address(helper.construct_dns_query(record['RDATA'], 1, rd), root, timeout, root)
                    if resolved_data is None:
                        return None
                    resolved_parsed = helper.parse_dns_response(resolved_data)     
                    if len(resolved_parsed['ANSWER']) > 0:
                        return construct_dns_response(data, resolved_data, question)
                else:
                    return data
        elif (len(parsed['AUTHORITY']) > 0): 
            # No answers but authority RRs exist
            # Resolving using the referral IP from authority records.
            record_found = False
            for record in parsed['AUTHORITY']:
                record_name = record['RDATA']
                # Filtering for existing Type A records in Additional
                filtered_data = [d for d in parsed['ADDITIONAL'] if d['TYPE'] == TYPE_A]
                for record in filtered_data:
                    if record.get('NAME') == record_name:
                        server_ip = record['RDATA']
                        record_found = True
                        break
                if len(filtered_data) > 0:
                    # No corresponding IP, get IP from Additional records.
                    server_ip = get_addtional_ip(filtered_data)
                    record_found = True
                if record_found:
                    break
                
                if record['TYPE'] not in helper.DNSTYPES:
                    # Disregarded record type (ie. SOA)
                    return data

                # Additional section couldn't resolve, resolving with Authority record
                print(f"RESOLVING {record_name} at {server_ip}")
                rd = False
                if ('rd' in parsed['HEADER']['FLAGS']):
                    rd = True
                resolved_data = resolve_address(helper.construct_dns_query(record_name, 1, rd), root, timeout, root)
                if (resolved_data == None):
                    return None
                parsed = helper.parse_dns_response(resolved_data)
                print(f"RESOLVED DATA {parsed}")
                if len(parsed['ANSWER']) > 0:
                    # Answers returned, updating server_ip and breaking
                    for record in parsed['ANSWER']:
                        server_ip = record['RDATA']
                    break
                elif parsed['HEADER']['RCODE'] > 0:
                    return resolved_data
        elif (len(parsed['ADDITIONAL']) > 0):
            # Trying the Additional section if Authentication and Answers are empty
            server_ip = get_addtional_ip(parsed['ADDITIONAL'])
        else:
            return None
            # No ANSWER, AUTHORITY, or ADDITIONAL data exists.  

def main():
    parser = argparse.ArgumentParser(description='DNS Resolver')
    parser.add_argument("resolver_port", type=int, help="Port number")
    parser.add_argument("--timeout", type=int, default=1, help="Timeout for DNS query in seconds (default: 1)")

    args = parser.parse_args()

    resolver_port = args.resolver_port
    timeout = args.timeout

    validated = helper.argument_validation(None, resolver_port)
    if validated != 1:
        print(validated)
        return

    root_servers = open_root();
    server_socket = socket.socket(AF_INET, SOCK_DGRAM)
    # Allow reusing the address to avoid errno 98
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1 )

    server_socket.bind((HOST, int(resolver_port)))
    print(f"The server is ready to receive at port {resolver_port}")

    while 1:
        # Waiting for data to arrive from the client
        query, client_address = server_socket.recvfrom(2048)
        print(f"Request received from: {client_address}")
        count = 0
        for server_ip in root_servers:
            print(server_ip)
            count += 1
            if count > 5:
                print("Root servers exhausted")
                break
            print(f"ROOT Server: {server_ip}")
            data = resolve_address(query, server_ip, timeout, server_ip)
            if data is not None:
                server_socket.sendto(data, client_address)
                parsed = helper.parse_dns_response(data)
                print(f"Sent response QID: {parsed['HEADER']['ID']} to {client_address} successfully.")
                break
        else:
            print("Server exhausted")
            server_socket.sendto(data, client_address)

if __name__ == "__main__":
    main()