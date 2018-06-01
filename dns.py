import binascii
import socket
import argparse


UDP_IP = "8.8.8.8"
UDP_PORT = 53

# documentation found at https://tools.ietf.org/html/rfc1035

def send_udp_message(message):
    message = message.replace(" ", "").replace("\n", "")
    message = binascii.unhexlify(message)

    # AF_INET: internet; SOCK_DGRAM: UDP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(message, (UDP_IP, UDP_PORT))
    data, _ = s.recvfrom(4096)
    s.close()

    return binascii.hexlify(data).decode("utf-8")


def make_request(url):
    header = "AA AA 01 00 00 01 00 00 00 00 00 00"

    # e.g. example in example.com
    domain = url.rsplit(".", 1)[0]
    domain = make_qname_section(domain)

    # e.g. com in example.com
    tld = url.rsplit(".", 1)[1]
    tld = make_qname_section(tld)

    terminal_byte = "00"
    qtype = "00 01" # A records
    qclass = "00 01" # Internet

    question = " ".join([domain, tld, terminal_byte, qtype, qclass])

    return " ".join([header, question]).strip()


def make_qname_section(section):
    length = '%02x'%len(section)
    ascii_dec = [ord(char) for char in section]
    ascii_hex = [format(dec, 'x') for dec in ascii_dec]
    ascii_hex.insert(0, length)

    return ' '.join(str(h) for h in ascii_hex)


def print_ip(hex):
    octets = [hex[i:i+2] for i in range(0, len(hex), 2)]
    ip_octets = octets[-4:]
    ip_ints = [int(h, 16) for h in ip_octets]

    print('.'.join(str(d) for d in ip_ints))


def main():
    parser = argparse.ArgumentParser(description='Send a dns request.')
    parser.add_argument("url", help="the url domain, e.g. example.com")
    args = parser.parse_args()

    request = make_request(args.url)
    response = send_udp_message(request)

    print_ip(response)


if __name__ == "__main__":
   main()
