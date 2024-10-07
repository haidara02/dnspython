import random
import struct
import re

DNSTYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX'}
UNUSEDTYPES = {6: 'SOA', 28: 'AAAA'}
DNSCLASSES = {1: 'IN'}
OPCODES = {0: 'QUERY', 1: "IQUERY", 2: "STATUS"}
RCODES = {0: 'NOERROR', 1: "FORMAT_ERROR", 2: "SERVER_FAILURE", 3: "NAME_ERROR", 4: "NOT_IMPLEMENTED", 5: "REFUSED"}

def lookup(search, dictionary):
    for key, value in dictionary.items():
        if value == search:
            return key
    return None

def argument_validation(ip, port):
    # Basic argument validation
    # Regex source: https://www.oreilly.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html
    if ip is not None:
        # On the resolver side
        if not (re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip) or ip == 'localhost'):
            return ("Error: invalid IPv4 address\nUsage: IPv4 address must be numeric and consist of 4 fields which are separated by dots")
    try:
        port = int(port)
        if ip is None and (port < 1024 or port > 65535):
            return ("Error: invalid port number\nUsage: port number must be between 1024 and 65535")
    except ValueError:
        return ("Error: invalid port number\nUsage: port number must be an integer")
    return 1

def encode_dns_address(name):
    encoded_domain = b''
    # Removing any trailing full stops
    if name[-1] == '.':
        name = name[:-1]
    # Encoding each label in the name
    for label in name.split('.'):
        encoded_domain += struct.pack('B', len(label)) + label.encode('utf-8')
    return encoded_domain + b'\x00'

def construct_dns_query(name, qtype, rd):
    # Generate a random 16-bit integer for the query ID
    qid = random.getrandbits(16)

    # Constructing the DNS query header
    flags = 0
    if rd is True:
        flags = 0x0100
    dns_query = encode_dns_sections([qid, flags, 1, 0, 0, 0], [qtype, 1], name)
    return dns_query

def encode_dns_sections(h_values, q_values, name):
    # Encoding of header and question taken and modified from: 
    # https://implement-dns.wizardzines.com/book/part_1.html 
    # struct.pack converts the provided arguments into a byte string
    # arguments consist of (ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
    header = b''
    for h in h_values:
        header += struct.pack('!H', h)
    question = encode_dns_address(name)
    for q in q_values:
        question += struct.pack('!H', q)
    # Combining the header and question sections to merge first two sections
    return header + question

def construct_dns_record(response, offset, count):
    records = []
    for i in range(count):
        # Decoding the record name and figuring out where it ends
        name, offset = decode_name(response, offset)
        # Unpack the record values as per RFC 1035
        record_values = struct.unpack('!HHLH', response[offset : offset + 10])
        record_keys = ['TYPE', 'CLASS', 'TTL', 'RDLENGTH']
        record = {key: value for key, value in zip(record_keys, record_values)}
        record['NAME'] = name
        if (record['TYPE'] == lookup('NS', DNSTYPES)) or (record['TYPE'] == lookup('CNAME', DNSTYPES)) or (record['TYPE'] == lookup('PTR', DNSTYPES)):
            record['RDATA'] = decode_name(response, offset + 10)[0]
        elif (record['TYPE'] == lookup('MX', DNSTYPES)):
            record['PREF'] = struct.unpack('!H', response[offset + 10 : offset + 12])[0]
            record['RDATA'] = decode_name(response, offset + 12)[0]
        elif (record['TYPE'] == lookup('A', DNSTYPES)):
            data = response[offset + 10 : offset + 10 + record['RDLENGTH']]
            record['RDATA'] = '.'.join(str(byte) for byte in data)
        else:
            record['RDATA'] = response[offset + 10 : offset + 10 + record['RDLENGTH']]
        offset += 10 + record['RDLENGTH']
        records.append(record)
    return records, offset

def decode_name(response, offset):
    name = ""
    while True:
        label_len = response[offset]
        if label_len == 0:
            # Empty label
            offset += 1
            break
        if (label_len & 0b1100_0000):
            # Two first bits are ones, meaning the label is a pointer.
            # Therefore decoding the pointer
            name += decode_label_pointer(label_len, response, offset)
            offset += 2
            break
        # Otherwise, decode the label using label_len    
        name += response[offset + 1 : offset + 1 + label_len].decode('utf-8') + '.'
        offset += label_len + 1
    return name, offset

def decode_label_pointer(length, response, offset):
    # Bitwise AND (&) operator is used to mask the 'length' bits with 0b0011_1111 (since labels must be 63 characters or less)
    # shift the 6 least significant bits left by 8 positions (<< 8)
    # then combine them with the next byte to form the pointer offset.
    pointer_offset = ((length & 0b0011_1111) << 8) | response[offset + 1]
    return decode_name(response, pointer_offset)[0]

def parse_dns_response(response):
    header_values = struct.unpack('!HHHHHH', response[:12])
    header_keys = ['ID', 'FLAGS', 'QUERY', 'ANSWER', 'AUTHORITY', 'ADDITIONAL']
    header = {key: value for key, value in zip(header_keys, header_values)}

    # Right shift (>> 11) and perform bitwise AND (& 0xF) to get the OPCODE
    header['OPCODE'] = (header['FLAGS'] >> 11) & 0xF

    flags = []
    # Extracting, checking flags for QR, AA, TC, RD or RA and appending them
    if ((header['FLAGS'] >> 15) & 0x1):
        flags.append('qr')
    if ((header['FLAGS'] >> 10) & 0x1):
        flags.append('aa')
    if ((header['FLAGS'] >> 9) & 0x1):
        flags.append('tc')
    if ((header['FLAGS'] >> 8) & 0x1):
        flags.append('rd')
    if ((header['FLAGS'] >> 7) & 0x1):
        flags.append('ra')
    header['RCODE'] = header['FLAGS'] & 0xF   
    header['FLAGS'] = flags

    # Shifting the offset to start after the header
    offset = 12

    # Decoding qname
    qname, offset = decode_name(response, offset)
    question_values = struct.unpack('!HH', response[offset : offset + 4])
    question_keys = ['TYPE', 'CLASS']
    question = {key: value for key, value in zip(question_keys, question_values)}
    question['NAME'] = qname

    # Shift the response to start after the question and start parsing RRs
    offset += 4
    answer_position = offset
    answers, offset = construct_dns_record(response, offset, header['ANSWER'])
    auths, offset = construct_dns_record(response, offset, header['AUTHORITY'])
    addits, offset = construct_dns_record(response, offset, header['ADDITIONAL'])
    
    data = {'HEADER': header, 'QUESTION': [question], 'ANSWER': answers, 'AUTHORITY': auths, 'ADDITIONAL': addits}
    return data
