#!/usr/bin/env python3
"""
`nameserver` implementation

@author: Aidan Schooling
@version:
"""

import argparse
import logging
from socket import AF_INET, SOCK_DGRAM, socket

HOST = "localhost"
PORT = 43053

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}

TTL_SEC = {
    "1s": 1,
    "1m": 60,
    "1h": 60 * 60,
    "1d": 60 * 60 * 24,
    "1w": 60 * 60 * 24 * 7,
    "1y": 60 * 60 * 24 * 365,
}


def val_to_n_bytes(value: int, n_bytes: int) -> tuple[int]:
    """
    Split a value into n bytes
    Return the result as a tuple of n integers
    """
    bytes = value.to_bytes(n_bytes, byteorder="big")
    
    listofbytes = []
    for i in range(n_bytes):
        listofbytes.append(bytes[i])
    
    return tuple(listofbytes)


def bytes_to_val(bytes_lst: list) -> int:
    """Merge n bytes into a value"""
    bytesall = bytes(bytes_lst)
    value = int.from_bytes(bytesall, byteorder="big")
    return value


def get_left_n_bits(bytes_lst: list, n_bits: int) -> int:
    """
    Extract first (leftmost) n bits of a two-byte sequence
    Return the result as a decimal value
    """
    if n_bits > 8:
        bits = bytes_lst[1] >> (8 - n_bits - 8)
    else:
        bits = bytes_lst[0] >> (8 - n_bits)

    
    return bits


def get_right_n_bits(bytes_lst: list, n_bits: int) -> int:
    """
    Extract last (rightmost) n bits of a two-byte sequence
    Return the result as a decimal value
    """
    if n_bits > 8:
        
        
        xbit = bytes_lst[0] & ((1 << (n_bits - 8)) - 1)
        bits = int((bin(xbit) + bin(bytes_lst[1])[:1] + bin(bytes_lst[1])[2:]), 2)
        

    else:
       
        bits = bytes_lst[1] & ((1 << n_bits) - 1)
    
    
    return bits


def read_zone_file(filename: str) -> tuple:
    """
    Read the zone file and build a dictionary
    Use domain names as keys and list(s) of records as values
    """
    zonedict = {}
    origin = ''
    defaultttl = ''
    current = ''
    with open(filename) as file:
        
        for line in file:
            
            splitlist = line.split()

            if splitlist[0] == '$ORIGIN':
                origin = splitlist[1]

            elif splitlist[0] == '$TTL':
                defaultttl = splitlist[1]
            
            if len(splitlist) == 5:
                current = splitlist[0]
                zonedict[splitlist[0]] = []
                zonedict[splitlist[0]].append(tuple(splitlist[1:]))

            elif len(splitlist) == 4 and not splitlist[0] in TTL_SEC:
                zonedict[splitlist[0]] = []
                current = splitlist[0]
                completelist = [defaultttl]
                completelist.extend(splitlist[1:])
                zonedict[splitlist[0]].append(tuple(completelist))

            elif len(splitlist) == 4 and splitlist[0] in TTL_SEC:
                zonedict[current].append(tuple(splitlist))




            
            elif len(splitlist) == 3:
                completelist = [defaultttl]
                completelist.extend(splitlist)
                zonedict[current].append(completelist)
            



         
            
  
    return (origin[:-1], zonedict)


def parse_request(origin: str, msg_req: bytes) -> tuple:
    """
    Parse the request
    Return query parameters as a tuple
    """
    bytesarray = bytearray(msg_req)
    
    transid = bytes_to_val(bytesarray[:2])
    del bytesarray[:12]
    lengthofdomain = bytes_to_val(bytesarray[:1])
    query = bytes(bytesarray)
    
    del bytesarray[:1]
    
    domain = bytesarray[:lengthofdomain].decode()
    del bytesarray[:lengthofdomain]

    origin2 = ''
    
    while bytes_to_val(bytesarray[:1]) != 0:

        distance = bytes_to_val(bytesarray[:1])

        origin2 += bytesarray[:distance+1].decode()[1:] + '.'
        del bytesarray[:1]
        del bytesarray[:distance]
    origin2 = origin2[:-1]
    print(origin2)
    
    del bytesarray[:1]

    if origin2 != origin:
        print('Hre')
        raise ValueError("Unknown origin")
    
    print(bytesarray)
    typenb = bytes_to_val(bytesarray[:2])

    if not typenb in DNS_TYPES:

        raise ValueError('Unknown query type')
    print(bytesarray[:4])
    if bytes_to_val(bytesarray[2:4]) != 1:
        raise ValueError('Unknown class')

    return (transid, domain, typenb, query)


def format_response(
    zone: dict, trans_id: int, qry_name: str, qry_type: int, qry: bytearray
) -> bytearray:
    """Format the response"""
    response = bytearray()

    bytetransid = bytearray(val_to_n_bytes(trans_id, 2))

    response.extend(bytetransid)
    

    
    standardresponse = 33024
    x = standardresponse.to_bytes(2, 'big')
    response.extend(x)
 
    single = 1

    response.extend(bytearray(val_to_n_bytes(single, 2)))

    nbofrr = 0
    answers = bytearray()
    for i in zone[qry_name]:

        if i[2] == DNS_TYPES[qry_type]:
           
            nbofrr += 1

            answer = bytearray()
            pointer = 49164
 
            answer.extend(bytearray(val_to_n_bytes(pointer, 2))) #pointer ---------------

            answer.extend(bytearray(val_to_n_bytes(qry_type, 2))) #type
            answer.extend(bytearray(val_to_n_bytes(1, 2))) #class
            answer.extend(bytearray(val_to_n_bytes(TTL_SEC[i[0]], 4))) #ttl
            if qry_type == 1:
                length = 4
                answer.extend(bytearray(val_to_n_bytes(length, 2))) #length
                address = i[3]
                splitaddress = address.split('.')
                for i in splitaddress:
                    answer.extend(bytearray(val_to_n_bytes(int(i), 1)))
            
            elif qry_type == 28:

                length = 16
                answer.extend(bytearray(val_to_n_bytes(length, 2))) #length
                address = i[3]
                splitaddress = address.split(':')

                for i in splitaddress:
                    answer.extend(bytearray.fromhex(i))
                

            answers.extend(answer)

    
    response.extend(bytearray(val_to_n_bytes(nbofrr, 2)))

    response.extend(bytearray(val_to_n_bytes(0, 4)))

    response.extend(qry)
    response.extend(answers)




    return bytes(response)


def run(filename: str) -> None:
    """Main server loop"""
    origin, zone = read_zone_file(filename)
    with socket(AF_INET, SOCK_DGRAM) as server_sckt:
        server_sckt.bind((HOST, PORT))
        print("Listening on %s:%d" % (HOST, PORT))

        while True:
            try:
                (request_msg, client_addr) = server_sckt.recvfrom(2048)
            except KeyboardInterrupt:
                print("Quitting")
                break
            try:
                print(f'Request recieved')
                trans_id, domain, qry_type, qry = parse_request(origin, request_msg)
                msg_resp = format_response(zone, trans_id, domain, qry_type, qry)
                server_sckt.sendto(msg_resp, client_addr)
            except ValueError as v_err:
                print(f"Ignoring the request: {v_err}")


def main():
    """Main function"""
    arg_parser = argparse.ArgumentParser(description="Parse arguments")
    arg_parser.add_argument("zone_file", type=str, help="Zone file")
    arg_parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable logging.DEBUG mode"
    )
    args = arg_parser.parse_args()

    logger = logging.getLogger("root")
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    logging.basicConfig(format="%(levelname)s: %(message)s", level=logger.level)

    run(args.zone_file)


if __name__ == "__main__":
    main()
