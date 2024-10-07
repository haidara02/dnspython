import socket
from socket import AF_INET, SOCK_DGRAM
import helper
from helper import DNSTYPES, DNSCLASSES, OPCODES, RCODES, UNUSEDTYPES, lookup
import re
import sys
import time
import argparse

def client_print_records(dataset, section):
    if len(dataset) > 0: 
        print(f"\n{section} SECTION:")
        for a in dataset:
            if section == "QUESTION":
                # Added fake_ttl for formatting/aligning reasons
                fake_ttl = ""
                print(f"{a['NAME']:<20} {fake_ttl:<10} {DNSCLASSES[a['CLASS']]:<5} {DNSTYPES[a['TYPE']]:<5}")
            elif (a['TYPE'] in DNSTYPES):
                print(f"{a['NAME']:<20} {a['TTL']:<10} {DNSCLASSES[a['CLASS']]:<5} {DNSTYPES[a['TYPE']]:<10}", end = " ")
                if a['TYPE'] == 15: # QTYPE MX, include PREFERENCE
                    print(f"{a['PREF']:<10}", end = " ")
                print(f"{a['RDATA']}")
            else:
                print(f"{a['NAME']:<20} {a['TTL']:<10} {DNSCLASSES[a['CLASS']]:<5} {UNUSEDTYPES[a['TYPE']]:<5}")
    return

def client_error_validation(code, name):
    ERRORCODES = {
        1: "Server was unable to interpret the query.",
        2: "Server was unable to process this query due to a problem with the name server.",
        3: f"Server can't find {name}",
        4: "Server does not support the requested kind of query.",
        5: "Server refuses to perform the specified operation for policy reasons."
    }
    if code not in ERRORCODES:
        return 1
    print(f'Error: {ERRORCODES[code]}')
    return 0

def main():
    parser = argparse.ArgumentParser(description='DNS Client')
    parser.add_argument("resolver_ip", help="IP address of DNS resolver")
    parser.add_argument("resolver_port", type=int, help="Port number of DNS resolver")
    parser.add_argument("name", help="Domain name")
    parser.add_argument("--type", choices=["A", "NS", "CNAME", "MX", "PTR"], default="A", help="Type of DNS query (default: A)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout for DNS query in seconds (default: 5)")
    parser.add_argument("--rd", action="store_true", help="Enable recursion (RD flag)")

    args = parser.parse_args()

    resolver_ip = args.resolver_ip
    resolver_port = args.resolver_port
    name = args.name
    qtype = args.type
    timeout = args.timeout
    rd = args.rd

    validated = helper.argument_validation(resolver_ip, resolver_port)
    if validated != 1:
        print(validated)
        return
    
    if (lookup(qtype, DNSTYPES)) is not None:
        qtype = lookup(qtype, DNSTYPES)
        if (qtype == 12):
            labels = name.split(".")
            reverse = ".".join(labels[::-1])
            # QTYPE = PTR, reverse address and append ".IN-ADDR.ARPA" 
            name = reverse + ".in-addr.arpa"
    else:
        qtype = 1;

    # Constructing the DNS query message
    dns_query = helper.construct_dns_query(name, qtype, rd)

    #Sending the DNS query to the resolver address (code from lab3)
    client_socket = socket.socket(AF_INET, SOCK_DGRAM)
    client_socket.settimeout(timeout)
    try:
        start = time.time()
        local = time.localtime()
        client_socket.sendto(dns_query, (resolver_ip, resolver_port))
        # Wait for the response
        response, _ = client_socket.recvfrom(2048)
        end = time.time()

        # Round-trip time in ms
        query_time = int((end - start) * 1000)
    except socket.timeout:
        print(f"Error[Timeout]: No response received within {timeout} seconds.")
        return
    

    # Parsing the response
    data = helper.parse_dns_response(response)

    header = data['HEADER']
    if client_error_validation(header['RCODE'], name) == 0:
        return
    question = data['QUESTION']

    # Displaying the results
    print(f"{question[0]['NAME']}\n")
    print(f"HEADER: opcode: {OPCODES[header['OPCODE']]}, status: {RCODES[header['RCODE']]}, id: {header['ID']}")
    print(f"flags: {', '.join(header['FLAGS'])}; QUERY: {header['QUERY']}, ANSWER: {header['ANSWER']}, AUTHORITY: {header['AUTHORITY']}, ADDITIONAL: {header['ADDITIONAL']}")
    client_print_records(question, 'QUESTION')
    client_print_records(data['ANSWER'], 'ANSWER')
    client_print_records(data['AUTHORITY'], 'AUTHORITY')
    client_print_records(data['ADDITIONAL'], 'ADDITIONAL')
    print(f"\nQuery Time: {query_time} msec\nSERVER: {resolver_ip}#{resolver_port} (UDP)")
    formatted_time = time.strftime(f"%a, %d %b %Y %H:%M:%S (Local Time)", local)
    print(f"WHEN: {formatted_time}")
    print(f"MSG Size received: {len(response)}")

if __name__ == "__main__":
    main()